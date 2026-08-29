"""Orchestrate native routing-artifact compilation from resolved data."""

from __future__ import annotations

import dataclasses
import hashlib
import os
import shutil
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar

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

    def tool_versions(self, cwd: Path) -> dict[str, str]:
        """Return auditable identities for the native tools used by a build.

        The two Go compilers built from source do not implement a version
        command, so their executable SHA-256 is the only reliable identity.
        The released engines expose stable version commands.  Test runners
        can declare deterministic stand-in versions without pretending to be
        executables on ``PATH``.
        """

        declared = getattr(self.runner, "tool_versions", None)
        if declared is not None:
            return _declared_tool_versions(declared)

        names = {
            "dlc": self.dlc,
            "geoip": self.geoip,
            "sing-box": self.sing_box,
            "mihomo": self.mihomo,
            "xray": self.xray,
        }
        version_commands = {
            "sing-box": (self.sing_box, "version"),
            "mihomo": (self.mihomo, "-v"),
            "xray": (self.xray, "version"),
        }
        versions: dict[str, str] = {}
        for name, executable in names.items():
            command = version_commands.get(name)
            if command is not None:
                try:
                    completed = self.runner.run(command, cwd)
                except ToolError:
                    # The pinned source-built tools have no version command;
                    # fall back to their binary digest below if an engine
                    # implementation similarly omits one.
                    pass
                else:
                    output = (completed.stdout or completed.stderr).strip()
                    if output:
                        versions[name] = output
                        continue
            versions[name] = _executable_sha256(executable)
        return versions


def _declared_tool_versions(versions: Mapping[str, str]) -> dict[str, str]:
    required = ("dlc", "geoip", "sing-box", "mihomo", "xray")
    result = {name: versions[name] for name in required if versions.get(name)}
    missing = sorted(set(required) - set(result))
    if missing:
        raise GenerationError(
            "native tool version declarations are missing: " + ", ".join(missing)
        )
    return result


def _executable_sha256(executable: str) -> str:
    path = Path(executable)
    if not path.is_file():
        resolved = shutil.which(executable)
        if resolved is None:
            raise GenerationError(
                f"cannot record version for native tool {executable!r}: not on PATH"
            )
        path = Path(resolved)
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise GenerationError(
            f"cannot record version for native tool {executable!r}: {error}"
        ) from error
    return f"sha256:{digest}"


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
    print(f"ru-routing: generating artifacts into {stage}...", flush=True)
    try:
        render_raw(rendered, stage)
        inputs = stage / ".compiler-inputs"
        xray = stage / "xray"
        sing_box = stage / "sing-box"
        mihomo = stage / "mihomo"
        xray.mkdir()

        # xray's two datasets share the same "geoip.dat" output path (the
        # lite variant is produced by renaming the shared compiler output to
        # "geoip-lite.dat" afterward), so unlike sing-box/mihomo -- which
        # write to per-dataset subdirectories -- the two datasets cannot
        # compile concurrently without a write race. Keep this loop
        # sequential.
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
        print(
            f"ru-routing: generated {len(relative_paths)} artifacts, "
            f"publishing to {destination}...",
            flush=True,
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
    print(f"ru-routing: compiling xray artifacts for {dataset_name}...", flush=True)
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
    categories = sorted(dataset.categories.items())
    print(
        f"ru-routing: compiling sing-box rule-sets for {dataset_name} "
        f"({len(categories)} categories)...",
        flush=True,
    )

    def _compile_one(item: tuple[str, Category]) -> None:
        category_name, category = item
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
        print(f"ru-routing:   sing-box {dataset_name}/{name} done", flush=True)

    _run_parallel(categories, _compile_one)


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
    categories = sorted(dataset.categories.items())
    print(
        f"ru-routing: compiling mihomo rule-sets for {dataset_name} "
        f"({len(categories)} categories)...",
        flush=True,
    )

    def _compile_one(item: tuple[str, Category]) -> None:
        category_name, category = item
        name = _safe_category_name(category_name)
        public_source = output / f"{name}.yaml"
        public_source.write_text(
            render_mihomo_yaml(category), encoding="utf-8", newline="\n"
        )
        for behavior, values in _mihomo_converter_inputs(category):
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
        print(f"ru-routing:   mihomo {dataset_name}/{name} done", flush=True)

    _run_parallel(categories, _compile_one)


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


_T = TypeVar("_T")


def _worker_count(item_count: int) -> int:
    """Bound the thread pool to a sane size for I/O-bound subprocess calls.

    Each work item blocks its worker thread on a native-compiler subprocess
    rather than on CPU work in the parent process, so a pool somewhat larger
    than the CPU count keeps more subprocesses in flight without
    over-subscribing the parent's own (light) bookkeeping work.
    """

    if item_count <= 1:
        return 1
    return max(1, min(item_count, (os.cpu_count() or 4) * 2))


def _run_parallel(items: Sequence[_T], work: Callable[[_T], None]) -> None:
    """Run ``work`` over ``items`` on a bounded thread pool.

    Subprocess calls release the GIL while waiting on the child process, so
    a thread pool shrinks wall-clock time for the large sequential chains of
    independent sing-box/mihomo/xray compiler invocations. The first
    exception raised by any worker propagates with its original type intact
    (``ThreadPoolExecutor`` futures preserve the raised exception object), so
    callers' existing ``except Exception`` cleanup handles it unchanged.
    """

    if not items:
        return
    max_workers = _worker_count(len(items))
    if max_workers == 1:
        for item in items:
            work(item)
        return
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(work, item) for item in items]
        try:
            for future in as_completed(futures):
                future.result()
        except BaseException:
            executor.shutdown(wait=False, cancel_futures=True)
            raise


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
