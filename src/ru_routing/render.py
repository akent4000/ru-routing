"""Deterministic portable source rendering for resolved routing datasets."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import Category, Dataset, RuleEntry, RuleKind
from .resolve import ResolvedBuild


class RepresentationError(ValueError):
    """Raised when a safety-critical rule cannot reach a target format."""


@dataclass(frozen=True)
class Representation:
    """One target-format decision for a resolved rule."""

    target: str
    category: str
    kind: RuleKind
    value: str
    represented: bool
    reason: str | None = None


@dataclass(frozen=True)
class RepresentationReport:
    """Deterministic target-compatibility accounting for a rendered dataset."""

    entries: tuple[Representation, ...]

    @property
    def losses(self) -> tuple[Representation, ...]:
        """Return rules that the target could not express."""

        return tuple(entry for entry in self.entries if not entry.represented)


_DOMAIN_KINDS = frozenset(
    {
        RuleKind.DOMAIN,
        RuleKind.DOMAIN_SUFFIX,
        RuleKind.DOMAIN_KEYWORD,
        RuleKind.DOMAIN_REGEX,
    }
)
_HIGH_PRECEDENCE_CATEGORIES = frozenset({"blocked", "malware", "phishing", "spy"})
_DLC_PREFIXES = {
    RuleKind.DOMAIN: "full",
    RuleKind.DOMAIN_SUFFIX: "domain",
    RuleKind.DOMAIN_KEYWORD: "keyword",
    RuleKind.DOMAIN_REGEX: "regexp",
}
_MIHOMO_PREFIXES = {
    RuleKind.DOMAIN: "DOMAIN",
    RuleKind.DOMAIN_SUFFIX: "DOMAIN-SUFFIX",
    RuleKind.CIDR: "IP-CIDR",
}
_RULE_ORDER = {
    RuleKind.DOMAIN: 0,
    RuleKind.DOMAIN_SUFFIX: 1,
    RuleKind.DOMAIN_KEYWORD: 2,
    RuleKind.DOMAIN_REGEX: 3,
    RuleKind.CIDR: 4,
}


def render_raw(build: ResolvedBuild, dist: Path) -> RepresentationReport:
    """Atomically replace ``dist/raw`` with readable lite and server lists.

    Rendering is deliberately restricted to the already resolved build; source
    policy and compiler execution belong to adjacent pipeline stages.
    """

    report = representation_report(build)
    _raise_for_high_precedence_losses(report)
    raw = Path(dist) / "raw"
    with _staged_directory(raw) as stage:
        for dataset_name, dataset in (("lite", build.lite), ("server", build.server)):
            _render_raw_dataset(dataset_name, dataset, stage)
    return report


def render_dlc_sources(dataset: Dataset, path: Path) -> RepresentationReport:
    """Atomically render v2fly domain-list-community category source files."""

    report = _report_for_dataset("dlc", dataset, _DOMAIN_KINDS)
    _raise_for_high_precedence_losses(report)
    destination = Path(path)
    with _staged_directory(destination) as stage:
        for category_name, category in _categories(dataset):
            entries = _entries(category.entries, _DOMAIN_KINDS)
            if entries:
                _write_text(
                    stage / _category_source_name(category_name), _dlc_text(entries)
                )
    return report


def render_geoip_config(dataset: Dataset, path: Path) -> RepresentationReport:
    """Write a v2fly geoip config that embeds all category CIDRs inline."""

    report = _report_for_dataset("geoip", dataset, frozenset({RuleKind.CIDR}))
    _raise_for_high_precedence_losses(report)
    config = {
        "input": [
            {
                "action": "add",
                "args": {
                    "ipOrCIDR": [
                        entry.value
                        for entry in _entries(category.entries, {RuleKind.CIDR})
                    ],
                    "name": category_name,
                },
                "type": "text",
            }
            for category_name, category in _categories(dataset)
            if _entries(category.entries, {RuleKind.CIDR})
        ],
        "output": [
            {
                "action": "output",
                "args": {"outputDir": ".", "outputName": "geoip.dat"},
                "type": "v2rayGeoIPDat",
            }
        ],
    }
    _write_text(Path(path), _json(config))
    return report


def render_singbox_json(category: Category) -> str:
    """Return a sing-box JSON ruleset source for one category."""

    rules: dict[str, list[str]] = {}
    field_for_kind = {
        RuleKind.DOMAIN: "domain",
        RuleKind.DOMAIN_SUFFIX: "domain_suffix",
        RuleKind.DOMAIN_KEYWORD: "domain_keyword",
        RuleKind.DOMAIN_REGEX: "domain_regex",
        RuleKind.CIDR: "ip_cidr",
    }
    for kind in _RULE_ORDER:
        values = [entry.value for entry in _entries(category.entries, {kind})]
        if values:
            rules[field_for_kind[kind]] = values
    return _json({"version": 1, "rules": [rules]})


def render_mihomo_yaml(category: Category) -> str:
    """Return a Mihomo classical-provider YAML source for one category."""

    unsupported = _entries(category.entries, _DOMAIN_KINDS - set(_MIHOMO_PREFIXES))
    if unsupported and category.name in _HIGH_PRECEDENCE_CATEGORIES:
        first = unsupported[0]
        raise RepresentationError(
            f"mihomo cannot represent {category.name} {first.kind.value}:{first.value}"
        )
    lines = ["payload:"]
    for kind in (RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX, RuleKind.CIDR):
        for entry in _entries(category.entries, {kind}):
            suffix = ",no-resolve" if kind == RuleKind.CIDR else ""
            lines.append(f"  - {_MIHOMO_PREFIXES[kind]},{entry.value}{suffix}")
    return "\n".join(lines) + "\n"


def representation_report(build: ResolvedBuild) -> RepresentationReport:
    """Report each format's ability to carry every relevant resolved rule."""

    reports = []
    for dataset in (build.lite, build.server):
        reports.extend(
            _report_for_dataset("raw", dataset, frozenset(_RULE_ORDER)).entries
        )
        reports.extend(_report_for_dataset("dlc", dataset, _DOMAIN_KINDS).entries)
        reports.extend(
            _report_for_dataset("geoip", dataset, frozenset({RuleKind.CIDR})).entries
        )
        reports.extend(
            _report_for_dataset("sing-box", dataset, frozenset(_RULE_ORDER)).entries
        )
        reports.extend(
            _report_for_dataset(
                "mihomo", dataset, frozenset(_MIHOMO_PREFIXES)
            ).entries
        )
    return RepresentationReport(tuple(sorted(reports, key=_representation_key)))


def _render_raw_dataset(dataset_name: str, dataset: Dataset, root: Path) -> None:
    for category_name, category in _categories(dataset):
        domain_entries = _entries(category.entries, _DOMAIN_KINDS)
        cidr_entries = _entries(category.entries, {RuleKind.CIDR})
        if domain_entries:
            _write_text(
                root / dataset_name / "domains" / _category_filename(category_name),
                _dlc_text(domain_entries),
            )
        if cidr_entries:
            _write_text(
                root / dataset_name / "ip" / _category_filename(category_name),
                "".join(f"{entry.value}\n" for entry in cidr_entries),
            )


def _report_for_dataset(
    target: str, dataset: Dataset, supported: frozenset[RuleKind]
) -> RepresentationReport:
    relevant = _target_relevant_kinds(target)
    decisions = tuple(
        Representation(
            target=target,
            category=category_name,
            kind=entry.kind,
            value=entry.value,
            represented=entry.kind in supported,
            reason=None if entry.kind in supported else "rule kind is unsupported",
        )
        for category_name, category in _categories(dataset)
        for entry in _entries(category.entries, relevant)
    )
    return RepresentationReport(decisions)


def _target_relevant_kinds(target: str) -> frozenset[RuleKind]:
    if target == "dlc":
        return _DOMAIN_KINDS
    if target == "geoip":
        return frozenset({RuleKind.CIDR})
    return frozenset(_RULE_ORDER)


def _raise_for_high_precedence_losses(report: RepresentationReport) -> None:
    for loss in report.losses:
        if loss.category in _HIGH_PRECEDENCE_CATEGORIES:
            raise RepresentationError(
                f"{loss.target} cannot represent "
                f"{loss.category} {loss.kind.value}:{loss.value}"
            )


def _categories(dataset: Dataset) -> tuple[tuple[str, Category], ...]:
    return tuple(sorted(dataset.categories.items()))


def _entries(
    entries: Iterable[RuleEntry], kinds: Iterable[RuleKind]
) -> tuple[RuleEntry, ...]:
    allowed = frozenset(kinds)
    return tuple(
        sorted(
            (entry for entry in entries if entry.kind in allowed),
            key=lambda entry: (
                _RULE_ORDER[entry.kind],
                entry.value,
                tuple(sorted(entry.attributes)),
                tuple(sorted(entry.memberships)),
                tuple(sorted(entry.sources)),
            ),
        )
    )


def _dlc_text(entries: Iterable[RuleEntry]) -> str:
    return "".join(
        f"{_DLC_PREFIXES[entry.kind]}:{entry.value}"
        f"{''.join(f' @{attribute}' for attribute in sorted(entry.attributes))}\n"
        for entry in entries
    )


def _category_filename(category_name: str) -> str:
    return f"{_category_source_name(category_name)}.txt"


def _category_source_name(category_name: str) -> str:
    if Path(category_name).name != category_name or category_name in {"", ".", ".."}:
        raise RepresentationError(f"unsafe category name {category_name!r}")
    return category_name


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2) + "\n"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _representation_key(entry: Representation) -> tuple[object, ...]:
    return (
        entry.target,
        entry.category,
        _RULE_ORDER[entry.kind],
        entry.value,
        entry.reason or "",
    )


class _staged_directory:
    """Replace one directory with a fully-written sibling staging directory."""

    def __init__(self, destination: Path) -> None:
        self.destination = destination
        self.stage: Path | None = None

    def __enter__(self) -> Path:
        self.destination.parent.mkdir(parents=True, exist_ok=True)
        self.stage = Path(
            tempfile.mkdtemp(
                prefix=f".{self.destination.name}.tmp-", dir=self.destination.parent
            )
        )
        return self.stage

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.stage is None:
            return
        if exc_type is not None:
            shutil.rmtree(self.stage, ignore_errors=True)
            return
        backup = self.destination.with_name(f".{self.destination.name}.previous")
        if backup.exists():
            shutil.rmtree(backup)
        try:
            if self.destination.exists():
                os.replace(self.destination, backup)
            os.replace(self.stage, self.destination)
        except OSError:
            if backup.exists() and not self.destination.exists():
                os.replace(backup, self.destination)
            raise
        else:
            if backup.exists():
                shutil.rmtree(backup)
