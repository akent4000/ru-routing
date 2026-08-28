"""Canonical normalization and deterministic rule provenance union."""

from __future__ import annotations

import ipaddress
import re
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Mapping, Protocol

from .config import SourceRegistry
from .fetch import FetchedSource
from .models import RuleEntry, RuleKind
from .parsers import GeodataReader, RawRule, parse_source


class NormalizationError(ValueError):
    """Raised when a parsed upstream rule is invalid after normalization."""


class RegexValidationError(ValueError):
    """Raised when the exact RE2 validator rejects or cannot check a pattern."""


class RegexValidator(Protocol):
    """Exact validator boundary for the regular-expression engine downstream uses."""

    def validate(self, pattern: str) -> None: ...


_RE2CHECK = Path(__file__).resolve().parents[2] / "tools" / "re2check" / "main.go"


@dataclass(frozen=True)
class GoRegexValidator:
    """Validate regexes with Go regexp.Compile, which implements RE2 syntax."""

    command: tuple[str, ...] = field(
        default_factory=lambda: ("go", "run", str(_RE2CHECK))
    )
    timeout_seconds: float = 10.0

    def validate(self, pattern: str) -> None:
        try:
            result = subprocess.run(
                (*self.command, pattern),
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout_seconds,
            )
        except FileNotFoundError as error:
            raise RegexValidationError("Go RE2 validator is unavailable") from error
        except subprocess.TimeoutExpired as error:
            raise RegexValidationError("Go RE2 validator timed out") from error
        if result.returncode:
            raise RegexValidationError("regular expression rejected by Go RE2")


GO_RE2_VALIDATOR = GoRegexValidator()


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
    """Return a lowercase ASCII IDNA hostname or raise NormalizationError."""

    if not isinstance(value, str):
        raise NormalizationError("domain must be a string")
    candidate = value.strip()
    if candidate.endswith("."):
        candidate = candidate[:-1]
        if candidate.endswith("."):
            raise NormalizationError("invalid domain")
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


def normalize_rule(
    raw: RawRule, *, regex_validator: RegexValidator | None = None
) -> RuleEntry:
    """Convert one context-rich raw rule into a strict canonical entry."""

    try:
        if raw.kind in (RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX):
            value = normalize_domain(raw.value)
        elif raw.kind == RuleKind.CIDR:
            value = str(ipaddress.ip_network(raw.value, strict=True))
        elif raw.kind == RuleKind.DOMAIN_KEYWORD:
            value = _normalize_keyword(raw.value)
        elif raw.kind == RuleKind.DOMAIN_REGEX:
            value = _normalize_regex(raw.value, regex_validator or GO_RE2_VALIDATOR)
        else:
            raise NormalizationError(f"unsupported rule kind {raw.kind!r}")
    except (NormalizationError, ValueError) as error:
        raise NormalizationError(f"{_context(raw)}: {error}") from error
    return RuleEntry(
        kind=raw.kind,
        value=value,
        sources=frozenset({raw.source}),
        attributes=raw.attributes,
        memberships=frozenset({(raw.source, raw.category)}),
    )


def normalize_sources(
    sources: Iterable[RawRule] | Iterable[FetchedSource],
    *,
    registry: SourceRegistry | None = None,
    geodata_reader: GeodataReader | None = None,
    regex_validator: RegexValidator | None = None,
) -> tuple[RuleEntry, ...]:
    """Normalize rules or resolve fetched sources through registry metadata."""

    items = tuple(sources)
    if not items:
        return ()
    if all(isinstance(item, RawRule) for item in items):
        raw_rules = items
    else:
        if registry is None:
            raise NormalizationError(
                "a SourceRegistry is required when normalizing fetched sources"
            )
        if not all(isinstance(item, FetchedSource) for item in items):
            raise NormalizationError("sources must be RawRule or FetchedSource values")
        raw_rules = tuple(
            rule
            for fetched in items
            for rule in parse_source(
                registry.resolve(fetched.name),
                fetched.object_paths,
                geodata_reader=geodata_reader,
            )
        )

    provenance: dict[tuple[RuleKind, str, frozenset[str], str], set[str]] = {}
    for raw in raw_rules:
        entry = normalize_rule(raw, regex_validator=regex_validator)
        _, category = next(iter(entry.memberships))
        key = (entry.kind, entry.value, entry.attributes, category)
        provenance.setdefault(key, set()).update(entry.sources)
    return tuple(
        RuleEntry(
            kind=kind,
            value=value,
            sources=frozenset(source_ids),
            attributes=attributes,
            memberships=frozenset((source, category) for source in source_ids),
        )
        for (kind, value, attributes, category), source_ids in sorted(
            provenance.items(),
            key=lambda item: (
                item[0][0].value,
                item[0][1],
                tuple(sorted(item[0][2])),
                item[0][3],
            ),
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


def _normalize_regex(value: str, validator: RegexValidator) -> str:
    if not isinstance(value, str) or not value:
        raise NormalizationError("invalid domain regular expression")
    validator.validate(value)
    return value


def _context(raw: RawRule) -> str:
    line = f":{raw.line}" if raw.line is not None else ""
    return f"{raw.source}: {raw.path}{line}"
