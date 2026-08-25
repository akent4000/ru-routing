"""Resolve normalized source memberships into deterministic routing datasets."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

from .config import CategoryPolicy
from .models import Category, Dataset, PolicyTier, RuleEntry, RuleKind


class ResolutionError(ValueError):
    """Raised when normalized entries cannot be resolved safely."""


@dataclass(frozen=True)
class Conflict:
    """One overlap between categories with a policy-precedence relationship."""

    higher_category: str
    lower_category: str
    higher_entry: RuleEntry
    lower_entry: RuleEntry


@dataclass(frozen=True)
class ConflictReport:
    """Deterministic conflict accounting before and after resolution."""

    overlaps_before: tuple[Conflict, ...]
    overlaps_after: tuple[Conflict, ...]
    resolved: tuple[Conflict, ...]

    @property
    def unresolved(self) -> tuple[Conflict, ...]:
        """Return remaining precedence conflicts that need validation attention."""

        return self.overlaps_after


@dataclass(frozen=True)
class ResolvedBuild:
    """The resolved lite/server datasets and their conflict provenance."""

    lite: Dataset
    server: Dataset
    conflicts: ConflictReport

    @property
    def conflict_report(self) -> ConflictReport:
        """Compatibility-friendly descriptive name for the conflict report."""

        return self.conflicts


_TIER_PRIORITY = {
    PolicyTier.DENY: 4,
    PolicyTier.EXPLICIT_BLOCKED: 3,
    PolicyTier.TRUSTED_DIRECT: 2,
    PolicyTier.THEMATIC: 1,
}


def resolve_datasets(
    rules: Iterable[RuleEntry], policy: CategoryPolicy
) -> ResolvedBuild:
    """Map normalized source memberships and resolve unsafe policy overlaps.

    Deny entries take ownership from blocked and trusted-direct categories.
    Explicit blocked entries similarly take ownership from trusted-direct
    categories.  Thematic categories intentionally retain server entries so
    operators can route selected services even when a broader direct rule also
    matches them.
    """

    categorized = _categorize(rules, policy)
    tiers = {name: policy.canonical_category(name).tier for name in categorized}
    conflicts_before = _conflicts(categorized, tiers)
    resolved_entries = _resolve_categories(categorized, tiers)
    conflicts_after = _conflicts(resolved_entries, tiers)
    report = ConflictReport(
        overlaps_before=conflicts_before,
        overlaps_after=conflicts_after,
        resolved=tuple(
            conflict for conflict in conflicts_before if conflict not in conflicts_after
        ),
    )

    lite = _dataset_for("lite", resolved_entries, policy)
    server = _dataset_for("server", resolved_entries, policy)
    assert_server_superset(lite, server)
    return ResolvedBuild(lite=lite, server=server, conflicts=report)


def assert_server_superset(lite: Dataset, server: Dataset) -> None:
    """Require every category shared by lite and server to contain lite entries."""

    for category_name in sorted(set(lite.categories) & set(server.categories)):
        missing = (
            lite.categories[category_name].entries
            - server.categories[category_name].entries
        )
        if missing:
            rendered = ", ".join(
                f"{entry.kind.value}:{entry.value}"
                for entry in _sorted_entries(missing)
            )
            raise ResolutionError(
                f"server category {category_name} is missing lite entries: {rendered}"
            )


def _categorize(
    rules: Iterable[RuleEntry], policy: CategoryPolicy
) -> dict[str, tuple[RuleEntry, ...]]:
    grouped: dict[str, dict[tuple[RuleKind, str, frozenset[str]], _Provenance]] = {}
    for rule in rules:
        for source, source_category in sorted(rule.memberships):
            try:
                mapping = policy.source_categories[f"{source}:{source_category}"]
            except KeyError as error:
                raise ResolutionError(
                    f"no category policy mapping for {source}:{source_category}"
                ) from error
            canonical = policy.canonical_category(mapping.canonical_category)
            category = grouped.setdefault(canonical.name, {})
            key = (rule.kind, rule.value, rule.attributes)
            provenance = category.setdefault(key, _Provenance())
            provenance.sources.add(source)
            provenance.memberships.add((source, source_category))

    return {
        name: tuple(
            RuleEntry(
                kind=kind,
                value=value,
                sources=frozenset(provenance.sources),
                attributes=attributes,
                memberships=frozenset(provenance.memberships),
            )
            for (kind, value, attributes), provenance in sorted(
                entries.items(), key=lambda item: _entry_key_from_parts(*item[0])
            )
        )
        for name, entries in sorted(grouped.items())
    }


@dataclass
class _Provenance:
    sources: set[str]
    memberships: set[tuple[str, str]]

    def __init__(self) -> None:
        self.sources = set()
        self.memberships = set()


def _resolve_categories(
    categorized: dict[str, tuple[RuleEntry, ...]], tiers: dict[str, PolicyTier]
) -> dict[str, tuple[RuleEntry, ...]]:
    resolved: dict[str, tuple[RuleEntry, ...]] = {}
    for category, entries in categorized.items():
        tier = tiers[category]
        blockers = tuple(
            blocker
            for blocker_category, blocker_entries in categorized.items()
            if _takes_ownership(tiers[blocker_category], tier)
            for blocker in blocker_entries
        )
        resolved[category] = tuple(
            replacement
            for entry in entries
            for replacement in _subtract_entry(entry, blockers)
        )
    return resolved


def _takes_ownership(higher: PolicyTier, lower: PolicyTier) -> bool:
    """Whether a higher tier must remove matching entries from a lower tier."""

    if _TIER_PRIORITY[higher] <= _TIER_PRIORITY[lower]:
        return False
    if lower == PolicyTier.THEMATIC:
        return False
    return lower in {PolicyTier.EXPLICIT_BLOCKED, PolicyTier.TRUSTED_DIRECT}


def _subtract_entry(
    entry: RuleEntry, blockers: tuple[RuleEntry, ...]
) -> tuple[RuleEntry, ...]:
    if entry.kind == RuleKind.CIDR:
        return _subtract_cidr(entry, blockers)
    if entry.kind in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
        if any(_domains_overlap(entry, blocker) for blocker in blockers):
            return ()
    elif any(_same_rule(entry, blocker) for blocker in blockers):
        return ()
    return (entry,)


def _subtract_cidr(
    entry: RuleEntry, blockers: tuple[RuleEntry, ...]
) -> tuple[RuleEntry, ...]:
    remaining = [ipaddress.ip_network(entry.value, strict=True)]
    for blocker in blockers:
        if blocker.kind != RuleKind.CIDR:
            continue
        excluded = ipaddress.ip_network(blocker.value, strict=True)
        if excluded.version != remaining[0].version:
            continue
        next_remaining = []
        for candidate in remaining:
            if not candidate.overlaps(excluded):
                next_remaining.append(candidate)
            elif candidate.subnet_of(excluded):
                continue
            else:
                next_remaining.extend(candidate.address_exclude(excluded))
        remaining = next_remaining
        if not remaining:
            break
    return tuple(
        RuleEntry(
            kind=RuleKind.CIDR,
            value=str(network),
            sources=entry.sources,
            attributes=entry.attributes,
            memberships=entry.memberships,
        )
        for network in sorted(remaining, key=_network_key)
    )


def _conflicts(
    categorized: dict[str, tuple[RuleEntry, ...]], tiers: dict[str, PolicyTier]
) -> tuple[Conflict, ...]:
    conflicts = [
        Conflict(
            higher_category=higher_category,
            lower_category=lower_category,
            higher_entry=higher_entry,
            lower_entry=lower_entry,
        )
        for higher_category, higher_entries in categorized.items()
        for lower_category, lower_entries in categorized.items()
        if _takes_ownership(tiers[higher_category], tiers[lower_category])
        for higher_entry in higher_entries
        for lower_entry in lower_entries
        if _entries_overlap(higher_entry, lower_entry)
    ]
    return tuple(sorted(conflicts, key=_conflict_key))


def _entries_overlap(first: RuleEntry, second: RuleEntry) -> bool:
    if first.kind == RuleKind.CIDR and second.kind == RuleKind.CIDR:
        first_network = ipaddress.ip_network(first.value, strict=True)
        second_network = ipaddress.ip_network(second.value, strict=True)
        return (
            first_network.version == second_network.version
            and first_network.overlaps(second_network)
        )
    return _domains_overlap(first, second)


def _domains_overlap(first: RuleEntry, second: RuleEntry) -> bool:
    if first.kind not in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
        return _same_rule(first, second)
    if second.kind not in {RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX}:
        return False
    if first.kind == RuleKind.DOMAIN and second.kind == RuleKind.DOMAIN:
        return first.value == second.value
    if first.kind == RuleKind.DOMAIN_SUFFIX and second.kind == RuleKind.DOMAIN_SUFFIX:
        return _is_domain_suffix(first.value, second.value) or _is_domain_suffix(
            second.value, first.value
        )
    exact, suffix = (
        (first.value, second.value)
        if first.kind == RuleKind.DOMAIN
        else (second.value, first.value)
    )
    return _is_domain_suffix(exact, suffix)


def _is_domain_suffix(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith(f".{suffix}")


def _same_rule(first: RuleEntry, second: RuleEntry) -> bool:
    return first.kind == second.kind and first.value == second.value


def _dataset_for(
    name: str,
    categorized: dict[str, tuple[RuleEntry, ...]],
    policy: CategoryPolicy,
) -> Dataset:
    return Dataset(
        {
            category_name: Category(category_name, frozenset(entries))
            for category_name, entries in sorted(categorized.items())
            if name in policy.canonical_category(category_name).datasets
        }
    )


def _entry_key_from_parts(
    kind: RuleKind, value: str, attributes: frozenset[str]
) -> tuple[str, str, tuple[str, ...]]:
    return kind.value, value, tuple(sorted(attributes))


def _entry_key(
    entry: RuleEntry,
) -> tuple[str, str, tuple[str, ...], tuple[tuple[str, str], ...]]:
    return (
        entry.kind.value,
        entry.value,
        tuple(sorted(entry.attributes)),
        tuple(sorted(entry.memberships)),
    )


def _sorted_entries(entries: Iterable[RuleEntry]) -> tuple[RuleEntry, ...]:
    return tuple(sorted(entries, key=_entry_key))


def _network_key(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def _conflict_key(conflict: Conflict) -> tuple[object, ...]:
    return (
        conflict.higher_category,
        conflict.lower_category,
        _entry_key(conflict.higher_entry),
        _entry_key(conflict.lower_entry),
    )
