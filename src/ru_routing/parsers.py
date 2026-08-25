"""Strict adapters for text routing-rule inputs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Protocol

from .models import RuleKind


class ParseError(ValueError):
    """Raised when an upstream text rule cannot be interpreted safely."""


class _NamedSource(Protocol):
    name: str


@dataclass(frozen=True)
class RawRule:
    """A source rule with enough context for precise validation errors."""

    source: str
    category: str
    kind: RuleKind
    value: str
    path: Path
    line: int


_DLC_KINDS = {
    "full": RuleKind.DOMAIN,
    "domain": RuleKind.DOMAIN_SUFFIX,
    "keyword": RuleKind.DOMAIN_KEYWORD,
    "regexp": RuleKind.DOMAIN_REGEX,
}


def parse_source(
    source: str | _NamedSource,
    paths: Mapping[str, tuple[Path, ...]],
) -> Iterable[RawRule]:
    """Yield source rules from plain lists and domain-list-community syntax.

    ``source`` may be a source ID or a fetched-source-like object exposing a
    ``name`` attribute.  Input category is retained on ``RawRule`` for the
    later category-resolution stage, while the original source ID remains the
    provenance identifier.
    """

    source_id = source if isinstance(source, str) else source.name
    if not isinstance(source_id, str) or not source_id:
        raise ParseError("source ID must be a non-empty string")
    for category, category_paths in paths.items():
        if not isinstance(category, str) or not category:
            raise ParseError(f"{source_id}: invalid category")
        for path in category_paths:
            yield from _parse_path(source_id, category, Path(path))


def _parse_path(source: str, category: str, path: Path) -> Iterable[RawRule]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ParseError(f"{source}: {path}: input is not UTF-8") from error
    except OSError as error:
        raise ParseError(f"{source}: {path}: cannot read input") from error

    for line_number, line in enumerate(lines, start=1):
        rule = _parse_line(source, category, path, line_number, line)
        if rule is not None:
            yield rule


def _parse_line(
    source: str, category: str, path: Path, line_number: int, line: str
) -> RawRule | None:
    text = line.partition("#")[0].strip()
    if not text:
        return None
    fields = text.split()
    value = fields[0]
    if any(not field.startswith("@") for field in fields[1:]):
        _raise(source, path, line_number, "unexpected text after rule value")

    prefix, separator, remainder = value.partition(":")
    if separator and prefix in _DLC_KINDS:
        if not remainder:
            _raise(source, path, line_number, "empty domain-list rule value")
        return RawRule(
            source=source,
            category=category,
            kind=_DLC_KINDS[prefix],
            value=remainder,
            path=path,
            line=line_number,
        )
    if separator and "/" not in value:
        _raise(source, path, line_number, f"unsupported rule kind {prefix!r}")

    return RawRule(
        source=source,
        category=category,
        kind=RuleKind.CIDR if "/" in value else RuleKind.DOMAIN,
        value=value,
        path=path,
        line=line_number,
    )


def _raise(source: str, path: Path, line: int, message: str) -> None:
    raise ParseError(f"{source}: {path}:{line}: {message}")
