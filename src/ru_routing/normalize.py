"""Canonical normalization and deterministic rule provenance union."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from types import MappingProxyType
from typing import Mapping

from .models import RuleEntry, RuleKind
from .parsers import RawRule, parse_source


class NormalizationError(ValueError):
    """Raised when a parsed upstream rule is invalid after normalization."""


# Rule kinds are the canonical compatibility marker.  A later renderer can
# report omitted kinds for its target without discarding them during parsing.
TARGET_COMPATIBILITY: Mapping[RuleKind, frozenset[str]] = MappingProxyType(
    {
        RuleKind.DOMAIN: frozenset({"xray", "sing-box", "mihomo"}),
        RuleKind.DOMAIN_SUFFIX: frozenset({"xray", "sing-box", "mihomo"}),
        RuleKind.CIDR: frozenset({"xray", "sing-box", "mihomo"}),
        RuleKind.DOMAIN_KEYWORD: frozenset({"xray", "sing-box"}),
        RuleKind.DOMAIN_REGEX: frozenset({"xray", "sing-box"}),
    }
)
_ASCII_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    """Return a lowercase ASCII IDNA hostname or raise ``NormalizationError``."""

    if not isinstance(value, str):
        raise NormalizationError("domain must be a string")
    candidate = value.strip().rstrip(".")
    if not candidate or candidate.startswith(".") or ".." in candidate:
        raise NormalizationError("invalid domain")
    try:
        canonical = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise NormalizationError("invalid domain") from error
    if len(canonical) > 253 or any(
        len(label) > 63 or not _ASCII_LABEL.fullmatch(label)
        for label in canonical.split(".")
    ):
        raise NormalizationError("invalid domain")
    return canonical


def normalize_rule(raw: RawRule) -> RuleEntry:
    """Convert one context-rich raw rule into a strict canonical entry."""

    try:
        if raw.kind in (RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX):
            value = normalize_domain(raw.value)
        elif raw.kind == RuleKind.CIDR:
            value = str(ipaddress.ip_network(raw.value, strict=True))
        elif raw.kind == RuleKind.DOMAIN_KEYWORD:
            value = _normalize_keyword(raw.value)
        elif raw.kind == RuleKind.DOMAIN_REGEX:
            value = _normalize_regex(raw.value)
        else:
            raise NormalizationError(f"unsupported rule kind {raw.kind!r}")
    except (NormalizationError, ValueError) as error:
        raise NormalizationError(
            f"{raw.source}: {raw.path}:{raw.line}: {error}"
        ) from error
    return RuleEntry(kind=raw.kind, value=value, sources=frozenset({raw.source}))


def normalize_sources(
    sources: Iterable[RawRule] | Iterable[object],
) -> tuple[RuleEntry, ...]:
    """Normalize rules (or fetched sources) and union duplicate provenance."""

    items = tuple(sources)
    if not items:
        return ()
    if all(isinstance(item, RawRule) for item in items):
        raw_rules = items
    else:
        raw_rules = tuple(
            rule
            for source in items
            for rule in parse_source(
                source, getattr(source, "object_paths")
            )
        )

    provenance: dict[tuple[RuleKind, str], set[str]] = {}
    for raw in raw_rules:
        entry = normalize_rule(raw)
        provenance.setdefault((entry.kind, entry.value), set()).update(entry.sources)
    return tuple(
        RuleEntry(kind=kind, value=value, sources=frozenset(sorted(source_ids)))
        for (kind, value), source_ids in sorted(
            provenance.items(), key=lambda item: (item[0][0].value, item[0][1])
        )
    )


def _normalize_keyword(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(character.isspace() for character in value)
    ):
        raise NormalizationError("invalid domain keyword")
    try:
        return value.strip().encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise NormalizationError("invalid domain keyword") from error


def _normalize_regex(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise NormalizationError("invalid domain regular expression")
    try:
        re.compile(value)
    except re.error as error:
        raise NormalizationError("invalid domain regular expression") from error
    return value
