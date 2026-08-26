"""Orchestrate native routing-artifact compilation from resolved data."""

from __future__ import annotations

import dataclasses
import os
import shutil
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import yaml

from .models import Category, Dataset, RuleKind, category_is_cidr_capable
from .render import (
    render_dlc_sources,
    render_geoip_config,
    render_mihomo_yaml,
    render_raw,
    render_singbox_json,
)
from .resolve import ResolvedBuild
from .tooling import CompletedTool, ToolError


class GenerationError(RuntimeError):
    """Raised when a complete native artifact tree cannot be produced."""


class ToolExecutor(Protocol):
    """Minimal native-tool boundary used by generation and validation."""

    def run(self, argv: Sequence[str], cwd: Path) -> CompletedTool:
        """Execute one argv in ``cwd``."""


@dataclass(frozen=True)
class NativeTools:
    """Pinned executable names and their argv-only runner."""

    runner: ToolExecutor
    dlc: str = "dlc"
    geoip: str = "geoip"
    sing_box: str = "sing-box"
    mihomo: str = "mihomo"
    xray: str = "xray"

    def __post_init__(self) -> None:
        for field_ in dataclasses.fields(self):
            if field_.name == "runner":
                continue
            if not getattr(self, field_.name):
                raise ValueError(f"{field_.name} executable must not be empty")


@dataclass(frozen=True)
class GeneratedArtifacts:
    """Stable paths published by one successful generation."""

    relative_paths: tuple[str, ...]


def generate_all(
    rendered: ResolvedBuild, dist: Path, tools: NativeTools
) -> GeneratedArtifacts:
    """Compile every native artifact and atomically replace ``dist``."""

    destination = Path(dist)
    stage = destination.with_name(f".{destination.name}.generate")
    previous = destination.with_name(f".{destination.name}.previous")
    _remove_tree(stage)
    stage.mkdir(parents=True)
    try:
        render_raw(rendered, stage)
        inputs = stage / ".compiler-inputs"
        xray = stage / "xray"
        sing_box = stage / "sing-box"
        mihomo = stage / "mihomo"
        xray.mkdir()

        for dataset_name, dataset in _datasets(rendered):
            _compile_xray(dataset_name, dataset, stage, inputs, xray, tools)
        for dataset_name, dataset in _datasets(rendered):
            _compile_sing_box(dataset_name, dataset, stage, sing_box, tools)
        for dataset_name, dataset in _datasets(rendered):
            _compile_mihomo(dataset_name, dataset, stage, inputs, mihomo, tools)

        _remove_tree(inputs)
        relative_paths = tuple(
            sorted(
                str(path.relative_to(stage))
                for path in stage.rglob("*")
                if path.is_file()
            )
        )
        _publish_tree(stage, destination, previous)
        return GeneratedArtifacts(relative_paths)
    except Exception:
        _remove_tree(stage)
        raise


def _compile_xray(
    dataset_name: str,
    dataset: Dataset,
    stage: Path,
    inputs: Path,
    output: Path,
    tools: NativeTools,
) -> None:
    source_root = inputs / "xray" / dataset_name
    geosite_source = source_root / "geosite"
    render_dlc_sources(dataset, geosite_source)
    geosite_name = "geosite-lite.dat" if dataset_name == "lite" else "geosite.dat"
    geosite_output = output / geosite_name
    _run_compiler(
        tools,
        [
            tools.dlc,
            f"--datapath={geosite_source}",
            f"--outputdir={output}",
            f"--outputname={geosite_name}",
        ],
        stage,
        geosite_output,
        "DLC",
    )

    geoip_config = source_root / "geoip.json"
    render_geoip_config(dataset, geoip_config)
    compiler_output = output / "geoip.dat"
    _run_compiler(
        tools,
        [tools.geoip, "-c", str(geoip_config)],
        output,
        compiler_output,
        "geoip",
    )
    if dataset_name == "lite":
        os.replace(compiler_output, output / "geoip-lite.dat")


def _compile_sing_box(
    dataset_name: str,
    dataset: Dataset,
    stage: Path,
    output_root: Path,
    tools: NativeTools,
) -> None:
    output = output_root / dataset_name
    output.mkdir(parents=True)
    for category_name, category in sorted(dataset.categories.items()):
        name = _safe_category_name(category_name)
        source = output / f"{name}.json"
        source.write_text(render_singbox_json(category), encoding="utf-8", newline="\n")
        binary = output / f"{name}.srs"
        _run_compiler(
            tools,
            [
                tools.sing_box,
                "rule-set",
                "compile",
                "--output",
                str(binary),
                str(source),
            ],
            stage,
            binary,
            "sing-box",
        )


def _compile_mihomo(
    dataset_name: str,
    dataset: Dataset,
    stage: Path,
    inputs: Path,
    output_root: Path,
    tools: NativeTools,
) -> None:
    output = output_root / dataset_name
    compiler_inputs = inputs / "mihomo" / dataset_name
    output.mkdir(parents=True)
    compiler_inputs.mkdir(parents=True)
    for category_name, category in sorted(dataset.categories.items()):
        name = _safe_category_name(category_name)
        public_source = output / f"{name}.yaml"
        public_source.write_text(
            render_mihomo_yaml(category), encoding="utf-8", newline="\n"
        )
        converter_inputs = _mihomo_converter_inputs(category)
        for behavior, values in converter_inputs:
            suffix = f"-{behavior}"
            source = compiler_inputs / f"{name}{suffix}.yaml"
            binary = output / f"{name}{suffix}.mrs"
            source.write_text(
                yaml.safe_dump(
                    {"payload": values},
                    allow_unicode=False,
                    default_flow_style=False,
                    sort_keys=False,
                ),
                encoding="utf-8",
                newline="\n",
            )
            _run_compiler(
                tools,
                [
                    tools.mihomo,
                    "convert-ruleset",
                    behavior,
                    "yaml",
                    str(source),
                    str(binary),
                ],
                stage,
                binary,
                "mihomo",
            )


def _mihomo_converter_inputs(
    category: Category,
) -> tuple[tuple[str, list[str]], ...]:
    exact = sorted(
        entry.value for entry in category.entries if entry.kind == RuleKind.DOMAIN
    )
    suffixes = sorted(
        f".{entry.value}"
        for entry in category.entries
        if entry.kind == RuleKind.DOMAIN_SUFFIX
    )
    cidrs = sorted(
        entry.value for entry in category.entries if entry.kind == RuleKind.CIDR
    )
    result: list[tuple[str, list[str]]] = []
    behaviors = mihomo_mrs_behaviors(category)
    if "domain" in behaviors:
        result.append(("domain", [*exact, *suffixes]))
    if "ipcidr" in behaviors:
        result.append(("ipcidr", cidrs))
    return tuple(result)


def mihomo_mrs_behaviors(category: Category) -> tuple[str, ...]:
    """Return lossless MRS projections supported by Mihomo for a category."""

    kinds = frozenset(entry.kind for entry in category.entries)
    unsupported_domain_kinds = frozenset(
        {RuleKind.DOMAIN_KEYWORD, RuleKind.DOMAIN_REGEX}
    )
    behaviors = []
    if (
        kinds & {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}
        and not kinds & unsupported_domain_kinds
    ):
        behaviors.append("domain")
    if category_is_cidr_capable(category):
        behaviors.append("ipcidr")
    return tuple(behaviors)


def _run_compiler(
    tools: NativeTools,
    argv: list[str],
    cwd: Path,
    output: Path,
    label: str,
) -> None:
    try:
        tools.runner.run(argv, cwd)
    except ToolError as error:
        raise GenerationError(f"{label} compiler failed: {error}") from error
    if not output.is_file() or output.stat().st_size == 0:
        raise GenerationError(f"{label} compiler did not create {output}")


def _datasets(build: ResolvedBuild) -> tuple[tuple[str, Dataset], ...]:
    return (("lite", build.lite), ("server", build.server))


def _safe_category_name(name: str) -> str:
    if not name or Path(name).name != name or name in {".", ".."}:
        raise GenerationError(f"unsafe category name {name!r}")
    return name


def _publish_tree(stage: Path, destination: Path, previous: Path) -> None:
    _remove_tree(previous)
    try:
        if destination.exists():
            os.replace(destination, previous)
        os.replace(stage, destination)
    except OSError:
        if previous.exists() and not destination.exists():
            os.replace(previous, destination)
        raise
    else:
        _remove_tree(previous)


def _remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
