"""Immutable normalized routing data shared by every pipeline stage."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class RuleKind(str, Enum):
    """The supported normalized routing rule kinds."""

    DOMAIN = "domain"
    DOMAIN_SUFFIX = "domain_suffix"
    DOMAIN_KEYWORD = "domain_keyword"
    DOMAIN_REGEX = "domain_regex"
    CIDR = "cidr"


class PolicyTier(str, Enum):
    """Conflict-resolution precedence for a canonical category."""

    DENY = "deny"
    EXPLICIT_BLOCKED = "explicit_blocked"
    TRUSTED_DIRECT = "trusted_direct"
    THEMATIC = "thematic"


@dataclass(frozen=True)
class RuleEntry:
    """One normalized domain or network rule and its source provenance."""

    kind: RuleKind
    value: str
    sources: frozenset[str]
    attributes: frozenset[str] = field(default_factory=frozenset)
    memberships: frozenset[tuple[str, str]] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", frozenset(self.sources))
        object.__setattr__(self, "attributes", frozenset(self.attributes))
        memberships = frozenset(self.memberships)
        if any(
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(part, str) and part for part in item)
            for item in memberships
        ):
            raise ValueError("rule memberships must be non-empty source/category pairs")
        if any(source not in self.sources for source, _ in memberships):
            raise ValueError("rule membership source must be present in provenance")
        object.__setattr__(self, "memberships", memberships)


@dataclass(frozen=True)
class Category:
    """A named collection of canonical routing entries."""

    name: str
    entries: frozenset[RuleEntry]

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", frozenset(self.entries))


@dataclass(frozen=True)
class Dataset:
    """A fully resolved collection of named routing categories."""

    categories: Mapping[str, Category]

    def __post_init__(self) -> None:
        object.__setattr__(self, "categories", MappingProxyType(dict(self.categories)))

    def to_canonical_json(self) -> bytes:
        """Return deterministic UTF-8 JSON suitable for content fingerprints."""

        categories = {
            name: {
                "entries": [
                    {
                        "kind": entry.kind.value,
                        "attributes": sorted(entry.attributes),
                        "memberships": [
                            {"category": category, "source": source}
                            for source, category in sorted(entry.memberships)
                        ],
                        "sources": sorted(entry.sources),
                        "value": entry.value,
                    }
                    for entry in sorted(
                        category.entries,
                        key=lambda item: (
                            item.kind.value,
                            item.value,
                            tuple(sorted(item.attributes)),
                            tuple(sorted(item.memberships)),
                            tuple(sorted(item.sources)),
                        ),
                    )
                ]
            }
            for name, category in sorted(self.categories.items())
        }
        return json.dumps(
            {"categories": categories},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


@dataclass(frozen=True)
class BuildInputs:
    """Immutable datasets passed into a build stage."""

    datasets: Mapping[str, Dataset]

    def __post_init__(self) -> None:
        object.__setattr__(self, "datasets", MappingProxyType(dict(self.datasets)))
