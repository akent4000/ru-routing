"""Semantic, native, checksum, and reproducibility validation."""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

import yaml

from .generate import (
    GenerationError,
    NativeTools,
    generate_all,
    mihomo_mrs_behaviors,
)
from .models import Dataset, RuleKind
from .resolve import ResolutionError, ResolvedBuild, assert_server_superset
from .tooling import ToolError


class ValidationError(RuntimeError):
    """Raised when a build is not safe to publish."""


@dataclass(frozen=True)
class ValidationThresholds:
    """Absolute validation requirements applied before anomaly baselines exist."""

    required_categories: Mapping[str, frozenset[str]] = field(default_factory=dict)
    minimum_category_entries: Mapping[tuple[str, str], int] = field(
        default_factory=dict
    )
    require_checksums: bool = False
    check_determinism: bool = True

    def __post_init__(self) -> None:
        required = {
            dataset: frozenset(categories)
            for dataset, categories in self.required_categories.items()
        }
        if any(dataset not in {"lite", "server"} for dataset in required):
            raise ValueError("required category dataset must be lite or server")
        minima = dict(self.minimum_category_entries)
        for (dataset, category), count in minima.items():
            if dataset not in {"lite", "server"} or not category:
                raise ValueError("minimum category key must identify lite/server")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError(
                    "minimum category count must be a non-negative integer"
                )
        object.__setattr__(self, "required_categories", MappingProxyType(required))
        object.__setattr__(
            self, "minimum_category_entries", MappingProxyType(minima)
        )


@dataclass(frozen=True)
class ValidationReport:
    """Deterministic summary of successful validation work."""

    category_counts: Mapping[tuple[str, str], int]
    required_artifacts: tuple[str, ...]
    checksum_entries: int
    native_checks: int
    deterministic: bool | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "category_counts", MappingProxyType(dict(self.category_counts))
        )


_DOMAIN_KINDS = frozenset(
    {
        RuleKind.DOMAIN,
        RuleKind.DOMAIN_SUFFIX,
        RuleKind.DOMAIN_KEYWORD,
        RuleKind.DOMAIN_REGEX,
    }
)
_FORBIDDEN_DEFAULTS = frozenset({"0.0.0.0/0", "::/0"})


def validate_build(
    build: ResolvedBuild,
    dist: Path,
    thresholds: ValidationThresholds,
    tools: NativeTools,
) -> ValidationReport:
    """Reject unsafe, incomplete, corrupt, unloadable, or unstable builds."""

    destination = Path(dist)
    category_counts = _validate_semantics(build, thresholds)
    required_artifacts = _required_artifacts(build)
    _validate_required_artifacts(destination, required_artifacts)
    checksum_entries = _validate_checksums(
        destination, require=thresholds.require_checksums
    )
    native_checks = _validate_native(build, destination, tools)
    deterministic: bool | None = None
    if thresholds.check_determinism:
        _validate_determinism(build, destination, tools)
        deterministic = True
    return ValidationReport(
        category_counts=category_counts,
        required_artifacts=required_artifacts,
        checksum_entries=checksum_entries,
        native_checks=native_checks,
        deterministic=deterministic,
    )


def _validate_semantics(
    build: ResolvedBuild, thresholds: ValidationThresholds
) -> dict[tuple[str, str], int]:
    if build.conflicts.unresolved:
        raise ValidationError(
            f"build contains {len(build.conflicts.unresolved)} unresolved conflicts"
        )
    try:
        assert_server_superset(build.lite, build.server)
    except ResolutionError as error:
        raise ValidationError(str(error)) from error

    counts: dict[tuple[str, str], int] = {}
    for dataset_name, dataset in _datasets(build):
        for category_name, category in sorted(dataset.categories.items()):
            counts[(dataset_name, category_name)] = len(category.entries)
            for entry in category.entries:
                if entry.kind == RuleKind.CIDR and entry.value in _FORBIDDEN_DEFAULTS:
                    raise ValidationError(
                        f"forbidden default route in {dataset_name}/{category_name}: "
                        f"{entry.value}"
                    )

    for dataset_name, categories in thresholds.required_categories.items():
        present = set(_dataset(build, dataset_name).categories)
        for category_name in sorted(categories - present):
            raise ValidationError(
                f"required category {dataset_name}/{category_name} is absent"
            )
    for key, minimum in sorted(thresholds.minimum_category_entries.items()):
        count = counts.get(key, 0)
        if count < minimum:
            dataset_name, category_name = key
            raise ValidationError(
                f"{dataset_name}/{category_name} has {count} entries; "
                f"minimum is {minimum}"
            )
    return counts


def _required_artifacts(build: ResolvedBuild) -> tuple[str, ...]:
    paths = {
        "xray/geoip-lite.dat",
        "xray/geosite-lite.dat",
        "xray/geoip.dat",
        "xray/geosite.dat",
    }
    for dataset_name, dataset in _datasets(build):
        for category_name, category in sorted(dataset.categories.items()):
            name = _safe_name(category_name)
            kinds = frozenset(entry.kind for entry in category.entries)
            paths.update(
                {
                    f"sing-box/{dataset_name}/{name}.json",
                    f"sing-box/{dataset_name}/{name}.srs",
                    f"mihomo/{dataset_name}/{name}.yaml",
                }
            )
            if kinds & _DOMAIN_KINDS:
                paths.add(f"raw/{dataset_name}/domains/{name}.txt")
            if RuleKind.CIDR in kinds:
                paths.add(f"raw/{dataset_name}/ip/{name}.txt")
            for behavior in mihomo_mrs_behaviors(category):
                paths.add(f"mihomo/{dataset_name}/{name}-{behavior}.mrs")
    return tuple(sorted(paths))


def _validate_required_artifacts(dist: Path, required: tuple[str, ...]) -> None:
    if not dist.is_dir():
        raise ValidationError(f"build directory is absent: {dist}")
    for relative in required:
        path = dist / relative
        if not path.is_file() or path.stat().st_size == 0:
            raise ValidationError(f"required artifact is absent or empty: {relative}")


def _validate_checksums(dist: Path, *, require: bool) -> int:
    checksum_file = dist / "SHA256SUMS"
    if not checksum_file.is_file():
        if require:
            raise ValidationError("required checksum file is absent: SHA256SUMS")
        return 0
    try:
        lines = checksum_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise ValidationError(f"cannot read SHA256SUMS: {error}") from error
    expected: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise ValidationError(f"malformed SHA256SUMS line {line_number}")
        digest, raw_path = parts
        if any(character not in "0123456789abcdef" for character in digest):
            raise ValidationError(f"malformed SHA256SUMS line {line_number}")
        relative = raw_path.lstrip(" *")
        _validate_checksum_path(relative, line_number)
        if relative in expected:
            raise ValidationError(f"duplicate checksum path: {relative}")
        expected[relative] = digest

    for relative, digest in sorted(expected.items()):
        path = dist / relative
        if not path.is_file():
            raise ValidationError(f"checksum target is absent: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != digest:
            raise ValidationError(f"checksum mismatch for {relative}")

    public_files = {
        str(path.relative_to(dist))
        for path in dist.rglob("*")
        if path.is_file() and path.name not in {"SHA256SUMS", "manifest.json"}
    }
    missing = public_files - set(expected)
    extra = set(expected) - public_files
    if missing:
        raise ValidationError(
            f"SHA256SUMS is missing {', '.join(sorted(missing))}"
        )
    if extra:
        raise ValidationError(f"SHA256SUMS has unknown {', '.join(sorted(extra))}")
    return len(expected)


def _validate_checksum_path(relative: str, line_number: int) -> None:
    path = Path(relative)
    if (
        not relative
        or path.is_absolute()
        or ".." in path.parts
        or relative in {"SHA256SUMS", "manifest.json"}
    ):
        raise ValidationError(f"unsafe SHA256SUMS path on line {line_number}")


def _validate_native(
    build: ResolvedBuild, dist: Path, tools: NativeTools
) -> int:
    work = dist.with_name(f".{dist.name}.validate")
    _remove_tree(work)
    work.mkdir(parents=True)
    checks = 0
    try:
        for dataset_name, dataset in _datasets(build):
            config = work / f"xray-{dataset_name}.json"
            config.write_text(
                _xray_config(dataset_name, dataset, dist), encoding="utf-8"
            )
            if _has_entries(dataset):
                _run_native(
                    tools,
                    [tools.xray, "run", "-test", "-config", str(config)],
                    work,
                    "Xray config validation",
                )
                checks += 1

        for dataset_name, dataset in _datasets(build):
            for category_name in sorted(dataset.categories):
                source = dist / "sing-box" / dataset_name / f"{category_name}.srs"
                output = work / "sing-box" / dataset_name / f"{category_name}.json"
                output.parent.mkdir(parents=True, exist_ok=True)
                _run_native(
                    tools,
                    [
                        tools.sing_box,
                        "rule-set",
                        "decompile",
                        "--output",
                        str(output),
                        str(source),
                    ],
                    work,
                    "sing-box rule-set load",
                )
                if not output.is_file() or output.stat().st_size == 0:
                    raise ValidationError(
                        f"sing-box did not decompile {source.relative_to(dist)}"
                    )
                checks += 1

        for dataset_name, dataset in _datasets(build):
            for category_name, category in sorted(dataset.categories.items()):
                for behavior in mihomo_mrs_behaviors(category):
                    source = (
                        dist
                        / "mihomo"
                        / dataset_name
                        / f"{category_name}-{behavior}.mrs"
                    )
                    output = (
                        work
                        / "mihomo"
                        / dataset_name
                        / f"{category_name}-{behavior}.txt"
                    )
                    output.parent.mkdir(parents=True, exist_ok=True)
                    _run_native(
                        tools,
                        [
                            tools.mihomo,
                            "convert-ruleset",
                            behavior,
                            "mrs",
                            str(source),
                            str(output),
                        ],
                        work,
                        "Mihomo MRS load",
                    )
                    if not output.is_file() or output.stat().st_size == 0:
                        raise ValidationError(
                            f"Mihomo did not decode {source.relative_to(dist)}"
                        )
                    checks += 1
            copied = work / "mihomo" / dataset_name
            shutil.copytree(
                dist / "mihomo" / dataset_name, copied, dirs_exist_ok=True
            )
            config = work / f"mihomo-{dataset_name}.yaml"
            config.write_text(
                _mihomo_config(dataset_name, dataset), encoding="utf-8"
            )
            _run_native(
                tools,
                [tools.mihomo, "-d", str(work), "-t", "-f", str(config)],
                work,
                "Mihomo config validation",
            )
            checks += 1
        return checks
    finally:
        _remove_tree(work)


def _xray_config(dataset_name: str, dataset: Dataset, dist: Path) -> str:
    suffix = "-lite" if dataset_name == "lite" else ""
    rules: list[dict[str, object]] = []
    domain_categories = [
        name
        for name, category in sorted(dataset.categories.items())
        if any(entry.kind in _DOMAIN_KINDS for entry in category.entries)
    ]
    cidr_categories = [
        name
        for name, category in sorted(dataset.categories.items())
        if any(entry.kind == RuleKind.CIDR for entry in category.entries)
    ]
    if domain_categories:
        rules.append(
            {
                "type": "field",
                "outboundTag": "direct",
                "domain": [
                    f"ext:{dist / f'xray/geosite{suffix}.dat'}:{category}"
                    for category in domain_categories
                ],
            }
        )
    if cidr_categories:
        rules.append(
            {
                "type": "field",
                "outboundTag": "direct",
                "ip": [
                    f"ext:{dist / f'xray/geoip{suffix}.dat'}:{category}"
                    for category in cidr_categories
                ],
            }
        )
    return json.dumps(
        {
            "log": {"loglevel": "none"},
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
            "routing": {"rules": rules},
        },
        ensure_ascii=True,
        indent=2,
    ) + "\n"


def _mihomo_config(dataset_name: str, dataset: Dataset) -> str:
    providers: dict[str, dict[str, object]] = {}
    for category_name, category in sorted(dataset.categories.items()):
        providers[f"{category_name}-yaml"] = {
            "type": "file",
            "behavior": "classical",
            "format": "yaml",
            "path": f"./mihomo/{dataset_name}/{category_name}.yaml",
        }
        for behavior in mihomo_mrs_behaviors(category):
            providers[f"{category_name}-{behavior}-mrs"] = {
                "type": "file",
                "behavior": behavior,
                "format": "mrs",
                "path": (
                    f"./mihomo/{dataset_name}/"
                    f"{category_name}-{behavior}.mrs"
                ),
            }
    return yaml.safe_dump(
        {
            "mixed-port": 7890,
            "mode": "rule",
            "log-level": "silent",
            "rule-providers": providers,
            "rules": ["MATCH,DIRECT"],
        },
        allow_unicode=False,
        default_flow_style=False,
        sort_keys=False,
    )


def _run_native(
    tools: NativeTools, argv: list[str], cwd: Path, label: str
) -> None:
    try:
        tools.runner.run(argv, cwd)
    except ToolError as error:
        raise ValidationError(f"{label} failed: {error}") from error


def _validate_determinism(
    build: ResolvedBuild, dist: Path, tools: NativeTools
) -> None:
    work = dist.with_name(f".{dist.name}.validate")
    _remove_tree(work)
    work.mkdir(parents=True)
    rebuild = work / "rebuild"
    try:
        try:
            generated = generate_all(build, rebuild, tools)
        except GenerationError as error:
            raise ValidationError(f"deterministic rebuild failed: {error}") from error
        for relative in generated.relative_paths:
            original = dist / relative
            repeated = rebuild / relative
            if not original.is_file() or original.read_bytes() != repeated.read_bytes():
                raise ValidationError(f"nondeterministic artifact: {relative}")
    finally:
        _remove_tree(work)


def _datasets(build: ResolvedBuild) -> tuple[tuple[str, Dataset], ...]:
    return (("lite", build.lite), ("server", build.server))


def _dataset(build: ResolvedBuild, name: str) -> Dataset:
    return build.lite if name == "lite" else build.server


def _has_entries(dataset: Dataset) -> bool:
    return any(category.entries for category in dataset.categories.values())


def _safe_name(name: str) -> str:
    if not name or Path(name).name != name or name in {".", ".."}:
        raise ValidationError(f"unsafe category name {name!r}")
    return name


def _remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
