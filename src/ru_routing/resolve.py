"""Resolve normalized source memberships into deterministic routing datasets."""

from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable

from .config import CategoryPolicy
from .models import Category, Dataset, PolicyTier, RuleEntry, RuleKind


class ResolutionError(ValueError):
    """Raised when normalized entries cannot be resolved safely."""


_DOTLESS_REGEX = re.compile(r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")


def _matches_only_dotless_hosts(pattern: str) -> bool:
    """Whether a domain regex provably cannot match any dotted hostname.

    Fail-closed blocker treatment exists because regex overlap cannot be
    decided in general.  The one shape upstream data actually ships -- a
    fully anchored single-label pattern such as geosite ``private``'s
    ``^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`` -- can be recognized exactly, and
    treating it as matching *every* host wipes whole lower-tier categories
    (live: lite:trackers 408 -> 0).  Recognize that exact grammar so dotted
    entries keep their tier resolution while genuine catch-all patterns stay
    fail-closed.
    """

    return pattern == _DOTLESS_REGEX.pattern


@dataclass(frozen=True)
class Conflict:
    """One overlap between categories with a policy-precedence relationship."""

    dataset: str
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

_DOMAIN_RULE_KINDS = frozenset(
    {
        RuleKind.DOMAIN,
        RuleKind.DOMAIN_SUFFIX,
        RuleKind.DOMAIN_KEYWORD,
        RuleKind.DOMAIN_REGEX,
    }
)


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

    categorized, blocker_pool = _categorize(rules, policy)
    # tiers spans every canonical category in the blocker pool, not just
    # the categories a given dataset publishes -- a blocker category
    # (e.g. server-only "blocked") must resolve its tier even when it is
    # absent from a dataset's own publication set.
    tiers = {name: policy.canonical_category(name).tier for name in blocker_pool}

    # Phase 1 (both datasets): resolve each dataset's publication set
    # against the pre-resolution blocker pool, and report "before"
    # conflicts from that same pool.
    resolved_datasets: dict[str, dict[str, tuple[RuleEntry, ...]]] = {}
    conflicts_before: list[Conflict] = []
    for dataset in ("lite", "server"):
        entries = categorized[dataset]
        # Built once and reused for both the "before" conflict report and
        # the resolution pass -- both read the same pre-resolution pool, so
        # rebuilding per call would double index-construction cost for no
        # benefit.
        before_indexes = _build_blocker_indexes(dataset, entries, blocker_pool, tiers)
        conflicts_before.extend(_conflicts(dataset, entries, before_indexes))
        resolved_datasets[dataset] = _resolve_categories(entries, before_indexes)

    # Rebuild the blocker pool from the phase-1 *resolved* output before
    # computing "after" conflicts: a blocker category's own entries may
    # have changed during its dataset's resolution (e.g. server's
    # "blocked" is itself subtracted against "spy"), and a category
    # published in both datasets must merge both resolved copies so
    # neither dataset's "after" pass sees a stale blocker. Per canonical
    # category, the union of every dataset's resolved entries is exactly
    # the "still-published-somewhere, post-resolution" blocker set.
    resolved_pool: dict[str, tuple[RuleEntry, ...]] = {}
    for dataset_categories in resolved_datasets.values():
        for name, entries in dataset_categories.items():
            resolved_pool[name] = tuple(
                dict.fromkeys((*resolved_pool.get(name, ()), *entries))
            )

    # Phase 2 (both datasets): report "after" conflicts against the
    # resolved pool.
    conflicts_after: list[Conflict] = []
    for dataset in ("lite", "server"):
        resolved = resolved_datasets[dataset]
        after_indexes = _build_blocker_indexes(dataset, resolved, resolved_pool, tiers)
        conflicts_after.extend(_conflicts(dataset, resolved, after_indexes))

    sorted_before = tuple(sorted(conflicts_before, key=_conflict_key))
    sorted_after = tuple(sorted(conflicts_after, key=_conflict_key))
    # `Conflict` is a frozen dataclass with RuleEntry fields, so it's
    # hashable -- use a set for the membership check below instead of
    # linear-scanning `sorted_after` (a tuple) once per element of
    # `sorted_before`, which turns this into an O(N*M) scan at scale (both
    # lists can be hundreds of thousands of entries on live data).
    after_set = frozenset(sorted_after)
    report = ConflictReport(
        overlaps_before=sorted_before,
        overlaps_after=sorted_after,
        resolved=tuple(
            conflict for conflict in sorted_before if conflict not in after_set
        ),
    )

    lite = _dataset_for(resolved_datasets["lite"])
    server = _dataset_for(resolved_datasets["server"])
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


_PublicationSets = dict[str, dict[str, tuple[RuleEntry, ...]]]
_BlockerPool = dict[str, tuple[RuleEntry, ...]]


def _categorize(
    rules: Iterable[RuleEntry], policy: CategoryPolicy
) -> tuple[_PublicationSets, _BlockerPool]:
    """Group normalized rules into per-dataset publication sets, plus a
    dataset-independent "blocker pool" of every canonical category's full
    entry set.

    A canonical category's ``datasets:`` scope controls what gets
    *published* in each dataset's output -- it must not also gate whether
    that category can still take conflict-resolution ownership over a
    higher-tier category shadowing a *different*, published category. For
    example ``blocked`` (EXPLICIT_BLOCKED) is now server-only in
    ``datasets:``, but must still subtract its entries from lite's ``ru``
    (TRUSTED_DIRECT): dropping that would make lite's resolved ``ru`` a
    strict superset of server's resolved ``ru`` (server still subtracts
    ``blocked``), violating the assert_server_superset invariant. The
    blocker pool is the fix: built once from every mapping regardless of
    its ``datasets:`` scope, and used as the blocker source in
    ``_build_blocker_indexes`` instead of the per-dataset publication set.
    """

    grouped: dict[
        str, dict[str, dict[tuple[RuleKind, str, frozenset[str]], _Provenance]]
    ] = {"lite": {}, "server": {}}
    pool: dict[str, dict[tuple[RuleKind, str, frozenset[str]], _Provenance]] = {}
    for rule in rules:
        for source, source_category in sorted(rule.memberships):
            try:
                mapping = policy.source_categories[f"{source}:{source_category}"]
            except KeyError as error:
                raise ResolutionError(
                    f"no category policy mapping for {source}:{source_category}"
                ) from error
            canonical = policy.canonical_category(mapping.canonical_category)
            key = (rule.kind, rule.value, rule.attributes)
            pool_category = pool.setdefault(canonical.name, {})
            pool_provenance = pool_category.setdefault(key, _Provenance())
            pool_provenance.sources.add(source)
            pool_provenance.memberships.add((source, source_category))
            for dataset in mapping.datasets:
                category = grouped[dataset].setdefault(canonical.name, {})
                provenance = category.setdefault(key, _Provenance())
                provenance.sources.add(source)
                provenance.memberships.add((source, source_category))

    def _materialize(
        categories: dict[str, dict[tuple[RuleKind, str, frozenset[str]], _Provenance]]
    ) -> dict[str, tuple[RuleEntry, ...]]:
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
            for name, entries in sorted(categories.items())
        }

    return (
        {dataset: _materialize(categories) for dataset, categories in grouped.items()},
        _materialize(pool),
    )


@dataclass
class _Provenance:
    sources: set[str]
    memberships: set[tuple[str, str]]

    def __init__(self) -> None:
        self.sources = set()
        self.memberships = set()


def _resolve_categories(
    categorized: dict[str, tuple[RuleEntry, ...]],
    indexes: dict[str, _BlockerIndex],
) -> dict[str, tuple[RuleEntry, ...]]:
    resolved: dict[str, tuple[RuleEntry, ...]] = {}
    for category, entries in categorized.items():
        index = indexes[category]
        resolved[category] = tuple(
            replacement
            for entry in entries
            for replacement in _subtract_entry(entry, index)
        )
    return resolved


def _takes_ownership(dataset: str, higher: PolicyTier, lower: PolicyTier) -> bool:
    """Whether a higher tier must remove matching entries from a lower tier."""

    if _TIER_PRIORITY[higher] <= _TIER_PRIORITY[lower]:
        return False
    if dataset == "server" and lower == PolicyTier.THEMATIC:
        return False
    return True


_Blocker = tuple[str, RuleEntry]
"""A blocker entry paired with the category it came from."""


@dataclass
class _BlockerIndex:
    """Fast-lookup structures over one lower category's blocker entries.

    Overlap decisions only ever depend on ``kind``/``value`` (see
    ``_entries_overlap``), so every structure here is keyed on those alone;
    each stored blocker keeps its source category alongside the
    ``RuleEntry`` for ``Conflict`` pair emission in ``_conflicts``.
    """

    exact_domains: dict[str, list[_Blocker]]
    suffix_trie: dict
    fail_closed: tuple[_Blocker, ...]
    # DOMAIN_REGEX blockers whose pattern matches only dotless hosts (see
    # ``_matches_only_dotless_hosts``).  These cannot overlap any dotted
    # candidate, so they are subtracted from dotted entries' perspective as
    # if absent, instead of failing the whole tier closed.
    dotless_regex: tuple[_Blocker, ...]
    cidr_by_version: dict[int, list[_Blocker]]
    # Sorted-by-start-address view of cidr_by_version, built lazily (only
    # when a CIDR conflict-pair query actually needs it -- _subtract_cidr's
    # geometric splitting doesn't). Interval-overlap queries against this
    # via _cidr_overlapping_blockers are O(log n + k) instead of the O(n)
    # full scan cidr_by_version would require per candidate -- matters when
    # a tier has tens of thousands of CIDR blockers (e.g. live "blocked").
    _cidr_sorted: dict[int, list[tuple[int, int, _Blocker]]] = field(
        default_factory=dict
    )
    _cidr_max_end: dict[int, list[int]] = field(default_factory=dict)


def _build_blocker_indexes(
    dataset: str,
    lower_categories: Iterable[str],
    blocker_source: dict[str, tuple[RuleEntry, ...]],
    tiers: dict[str, PolicyTier],
) -> dict[str, _BlockerIndex]:
    """Build one ``_BlockerIndex`` per category in ``lower_categories``,
    sharing builds across categories whose blocker set is identical.

    Blockers are drawn from ``blocker_source`` -- the dataset-independent
    "blocker pool" of every canonical category's full entry set (see
    ``_categorize``), not the dataset's own publication set -- so a
    higher-tier category can take conflict-resolution ownership over a
    lower-tier one even when the higher-tier category itself is not
    published in this dataset (e.g. ``blocked`` is server-only but must
    still subtract from lite's ``ru``).

    ``_takes_ownership(dataset, blocker_tier, tier)`` depends only on
    ``tier`` (and the fixed ``dataset``), so every category at the same
    tier sees exactly the same set of blocker categories/entries. Live
    data has few tiers but potentially many categories per tier (e.g.
    several THEMATIC categories all shadowed by the same DENY/
    EXPLICIT_BLOCKED categories) -- building the index once per tier
    instead of once per category avoids duplicating multi-million-entry
    blocker structures (exact_domains dict, suffix trie) across every
    category that happens to share the same blockers.
    """

    indexes_by_tier: dict[PolicyTier, _BlockerIndex] = {}
    indexes: dict[str, _BlockerIndex] = {}
    for category in lower_categories:
        tier = tiers[category]
        if tier in indexes_by_tier:
            indexes[category] = indexes_by_tier[tier]
            continue
        exact_domains: dict[str, list[_Blocker]] = {}
        suffix_trie: dict = {}
        fail_closed: list[_Blocker] = []
        dotless_regex: list[_Blocker] = []
        cidr_by_version: dict[int, list[_Blocker]] = {}
        for blocker_category, blocker_entries in blocker_source.items():
            if not _takes_ownership(dataset, tiers[blocker_category], tier):
                continue
            for blocker in blocker_entries:
                item = (blocker_category, blocker)
                if blocker.kind == RuleKind.DOMAIN:
                    exact_domains.setdefault(blocker.value, []).append(item)
                    _domain_trie_insert(suffix_trie, item)
                elif blocker.kind == RuleKind.DOMAIN_SUFFIX:
                    _suffix_trie_insert(suffix_trie, item)
                elif blocker.kind == RuleKind.DOMAIN_REGEX and (
                    _matches_only_dotless_hosts(blocker.value)
                ):
                    dotless_regex.append(item)
                elif blocker.kind in (RuleKind.DOMAIN_KEYWORD, RuleKind.DOMAIN_REGEX):
                    fail_closed.append(item)
                elif blocker.kind == RuleKind.CIDR:
                    network = ipaddress.ip_network(blocker.value, strict=True)
                    cidr_by_version.setdefault(network.version, []).append(item)
        index = _BlockerIndex(
            exact_domains=exact_domains,
            suffix_trie=suffix_trie,
            fail_closed=tuple(fail_closed),
            dotless_regex=tuple(dotless_regex),
            cidr_by_version=cidr_by_version,
        )
        indexes_by_tier[tier] = index
        indexes[category] = index
    return indexes


def _suffix_trie_insert(trie: dict, item: _Blocker) -> None:
    _, blocker = item
    labels = tuple(reversed(blocker.value.split(".")))
    node = _trie_walk_and_mark(trie, labels)
    node.setdefault("terminal", []).append(item)


def _domain_trie_insert(trie: dict, item: _Blocker) -> None:
    """Thread a DOMAIN blocker's own label path through the suffix trie.

    Not a suffix terminal (a DOMAIN value never blocks a narrower
    candidate the way a DOMAIN_SUFFIX would), but its presence must be
    discoverable when a DOMAIN_SUFFIX candidate is a strict ancestor of
    this DOMAIN value -- matches the original ``_domains_overlap``
    DOMAIN-under-candidate-SUFFIX check.
    """

    _, blocker = item
    labels = tuple(reversed(blocker.value.split(".")))
    node = _trie_walk_and_mark(trie, labels)
    node.setdefault("domain_terminal", []).append(item)


def _trie_walk_and_mark(trie: dict, labels: tuple[str, ...]) -> dict:
    node = trie
    node["has_descendant_terminal"] = True
    for label in labels:
        node = node.setdefault("children", {}).setdefault(label, {})
        node["has_descendant_terminal"] = True
    return node


def _suffix_trie_has_overlap(
    trie: dict, value: str, *, candidate_is_suffix: bool
) -> bool:
    """O(depth) boolean overlap check -- never materializes a match list.

    Used by ``_is_blocked`` (the ``_resolve_categories`` fast path), which
    only needs to know *whether* an entry is blocked, not which blockers
    matched. Mirrors ``_suffix_trie_lookup``'s traversal exactly, just
    short-circuiting on the first hit instead of collecting every match --
    this matters at scale: a broad candidate (e.g. a single-label TLD
    suffix) can be a strict ancestor of hundreds of thousands of blocker
    entries, and materializing that whole subtree for a boolean answer is
    the difference between O(depth) and O(subtree size) per entry.
    """

    labels = tuple(reversed(value.split(".")))
    node = trie
    for label in labels:
        children = node.get("children")
        if not children or label not in children:
            return False
        node = children[label]
        if "terminal" in node:
            return True
    if candidate_is_suffix:
        if node.get("domain_terminal"):
            return True
        if node.get("children") and node.get("has_descendant_terminal"):
            return True
    return False


def _suffix_trie_lookup(
    trie: dict, value: str, *, candidate_is_suffix: bool
) -> list[_Blocker]:
    """Return blocker items whose DOMAIN_SUFFIX overlaps ``value``.

    Walks the reversed-label trie one label at a time. A terminal node
    visited along the way means ``value`` is equal to or narrower than a
    blocker suffix (covers DOMAIN-under-SUFFIX and narrower-SUFFIX-under-
    broader-SUFFIX). If every label of ``value`` is consumed and the
    landing node has descendants, ``value`` is itself a strict ancestor of
    some blocker suffix -- only relevant when ``value`` is itself a
    DOMAIN_SUFFIX (a DOMAIN value is never treated as broader than a
    blocker suffix, matching the original ``_domains_overlap`` semantics).

    This materializes every matching blocker and is used only where the
    actual blocker objects are needed (``_matching_blockers``, for
    ``Conflict`` pair emission) -- prefer ``_suffix_trie_has_overlap`` for a
    pure boolean check, since collecting a huge descendant subtree just to
    discard it is the difference between O(depth) and O(subtree size).
    """

    labels = tuple(reversed(value.split(".")))
    node = trie
    matches: list[_Blocker] = []
    for label in labels:
        children = node.get("children")
        if not children or label not in children:
            return matches
        node = children[label]
        if "terminal" in node:
            matches.extend(node["terminal"])
    if candidate_is_suffix:
        # A DOMAIN blocker with the exact same value as this DOMAIN_SUFFIX
        # candidate also overlaps (matches the original _is_domain_suffix's
        # `domain == suffix` branch, reached when the DOMAIN side is the
        # blocker and the DOMAIN_SUFFIX side is the candidate).
        matches.extend(node.get("domain_terminal", ()))
        if node.get("children") and node.get("has_descendant_terminal"):
            # `value`'s own terminal match (if any, added above) covers
            # value-is-narrower-than-or-equal-to-a-blocker-suffix;
            # descendants below this node are a genuinely separate case
            # (value is a strict ancestor of some blocker suffix/domain)
            # and must be collected regardless of whether a terminal match
            # was already found here.
            for child in node["children"].values():
                matches.extend(_collect_terminals(child))
    return matches


def _collect_terminals(node: dict) -> list[_Blocker]:
    collected: list[_Blocker] = list(node.get("terminal", ()))
    collected.extend(node.get("domain_terminal", ()))
    for child in node.get("children", {}).values():
        collected.extend(_collect_terminals(child))
    return collected


def _is_blocked(entry: RuleEntry, index: _BlockerIndex) -> bool:
    if entry.kind == RuleKind.CIDR:
        raise AssertionError("CIDR entries must use _subtract_cidr, not _is_blocked")
    if index.fail_closed:
        return True
    if entry.kind in (RuleKind.DOMAIN_KEYWORD, RuleKind.DOMAIN_REGEX):
        # Fail-closed: a KEYWORD/REGEX entry overlaps ANY other domain-kind
        # blocker unconditionally (matches _entries_overlap's
        # kind-membership check), not just other KEYWORD/REGEX blockers.
        # A dotless-only regex blocker does match a dotless KEYWORD/REGEX
        # candidate, so it counts toward the same fail-closed answer.
        return (
            bool(index.exact_domains)
            or _suffix_trie_has_any(index.suffix_trie)
            or bool(index.dotless_regex)
        )
    if entry.kind == RuleKind.DOMAIN:
        if entry.value in index.exact_domains:
            return True
        if index.dotless_regex and "." not in entry.value:
            return True
        return _suffix_trie_has_overlap(
            index.suffix_trie, entry.value, candidate_is_suffix=False
        )
    if entry.kind == RuleKind.DOMAIN_SUFFIX:
        if index.dotless_regex and "." not in entry.value:
            return True
        return _suffix_trie_has_overlap(
            index.suffix_trie, entry.value, candidate_is_suffix=True
        )
    raise AssertionError(f"unhandled rule kind {entry.kind!r}")


def _suffix_trie_has_any(trie: dict) -> bool:
    return bool(trie.get("has_descendant_terminal"))


def _cidr_sorted_view(
    index: _BlockerIndex, version: int
) -> tuple[list[tuple[int, int, _Blocker]], list[int]]:
    """Build (and cache) a sorted-by-start-address view of one IP version's
    CIDR blockers, plus a running-max-end array, for interval-overlap
    queries. Built lazily since the boolean/geometric ``_subtract_cidr``
    path never needs it.
    """

    if version not in index._cidr_sorted:
        sortable = sorted(
            (
                (
                    int(network.network_address),
                    int(network.broadcast_address),
                    item,
                )
                for item in index.cidr_by_version.get(version, ())
                for network in (ipaddress.ip_network(item[1].value, strict=True),)
            ),
            key=lambda triple: triple[0],
        )
        index._cidr_sorted[version] = sortable
        running_max = 0
        max_ends = []
        for _, end, _ in sortable:
            running_max = max(running_max, end)
            max_ends.append(running_max)
        index._cidr_max_end[version] = max_ends
    return index._cidr_sorted[version], index._cidr_max_end[version]


def _cidr_overlapping_blockers(
    index: _BlockerIndex, network: ipaddress.IPv4Network | ipaddress.IPv6Network
) -> tuple[_Blocker, ...]:
    """Return every CIDR blocker whose address range overlaps ``network``.

    Two CIDR networks overlap iff their [start, end] address ranges
    intersect (a CIDR network is a contiguous, power-of-two-aligned address
    range, so range intersection is equivalent to ``ip_network.overlaps``).
    Blockers are pre-sorted by start address; a binary search finds the
    first blocker whose start could still be within the candidate's range,
    and a running max-end array lets the scan stop as soon as no remaining
    blocker (even the one with the largest end seen so far) could still
    reach back to overlap -- avoiding an O(n) scan per candidate when only
    a handful of blockers actually overlap.
    """

    query_start = int(network.network_address)
    query_end = int(network.broadcast_address)
    sorted_blockers, max_ends = _cidr_sorted_view(index, network.version)
    if not sorted_blockers:
        return ()
    starts = [triple[0] for triple in sorted_blockers]
    # Blockers starting after query_end can never overlap (start > end).
    upper = bisect.bisect_right(starts, query_end)
    matches: list[_Blocker] = []
    for position in range(upper - 1, -1, -1):
        if max_ends[position] < query_start:
            # No blocker at or before this position can reach query_start.
            break
        blocker_start, blocker_end, item = sorted_blockers[position]
        if blocker_end >= query_start:
            matches.append(item)
    return tuple(matches)


def _matching_blockers(entry: RuleEntry, index: _BlockerIndex) -> tuple[_Blocker, ...]:
    if entry.kind == RuleKind.CIDR:
        network = ipaddress.ip_network(entry.value, strict=True)
        return _cidr_overlapping_blockers(index, network)
    if entry.kind in (RuleKind.DOMAIN_KEYWORD, RuleKind.DOMAIN_REGEX):
        matched: list[_Blocker] = list(index.fail_closed)
        # A dotless-only regex blocker matches any dotless KEYWORD/REGEX
        # candidate (both are single-label host grammars).
        matched.extend(index.dotless_regex)
        for domain_blockers in index.exact_domains.values():
            matched.extend(domain_blockers)
        matched.extend(_collect_terminals(index.suffix_trie))
        return tuple(matched)
    matched = list(index.fail_closed)
    dotless = entry.kind in (RuleKind.DOMAIN, RuleKind.DOMAIN_SUFFIX) and (
        "." not in entry.value
    )
    if dotless:
        matched.extend(index.dotless_regex)
    if entry.kind == RuleKind.DOMAIN:
        matched.extend(index.exact_domains.get(entry.value, ()))
        matched.extend(
            _suffix_trie_lookup(
                index.suffix_trie, entry.value, candidate_is_suffix=False
            )
        )
    elif entry.kind == RuleKind.DOMAIN_SUFFIX:
        matched.extend(
            _suffix_trie_lookup(
                index.suffix_trie, entry.value, candidate_is_suffix=True
            )
        )
    else:
        raise AssertionError(f"unhandled rule kind {entry.kind!r}")
    return tuple(matched)


def _subtract_entry(entry: RuleEntry, index: _BlockerIndex) -> tuple[RuleEntry, ...]:
    if entry.kind == RuleKind.CIDR:
        return _subtract_cidr(entry, index)
    if _is_blocked(entry, index):
        return ()
    return (entry,)


def _subtract_cidr(entry: RuleEntry, index: _BlockerIndex) -> tuple[RuleEntry, ...]:
    network = ipaddress.ip_network(entry.value, strict=True)
    remaining = [network]
    # Use the interval index to fetch only blockers whose range actually
    # overlaps `network`, instead of scanning every CIDR blocker for this
    # tier -- the same O(n) scan that made conflict-pair emission slow at
    # live scale (tens of thousands of CIDR entries on both sides) applies
    # here too, since this function is called once per CIDR candidate.
    for _, blocker in _cidr_overlapping_blockers(index, network):
        excluded = ipaddress.ip_network(blocker.value, strict=True)
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
            value=str(remaining_network),
            sources=entry.sources,
            attributes=entry.attributes,
            memberships=entry.memberships,
        )
        for remaining_network in sorted(remaining, key=_network_key)
    )


def _conflicts(
    dataset: str,
    categorized: dict[str, tuple[RuleEntry, ...]],
    indexes: dict[str, _BlockerIndex],
) -> tuple[Conflict, ...]:
    conflicts: list[Conflict] = []
    for lower_category, lower_entries in categorized.items():
        index = indexes[lower_category]
        for lower_entry in lower_entries:
            for higher_category, higher_entry in _matching_blockers(lower_entry, index):
                conflicts.append(
                    Conflict(
                        dataset=dataset,
                        higher_category=higher_category,
                        lower_category=lower_category,
                        higher_entry=higher_entry,
                        lower_entry=lower_entry,
                    )
                )
    return tuple(sorted(conflicts, key=_conflict_key))


def _entries_overlap(first: RuleEntry, second: RuleEntry) -> bool:
    if first.kind == RuleKind.CIDR and second.kind == RuleKind.CIDR:
        first_network = ipaddress.ip_network(first.value, strict=True)
        second_network = ipaddress.ip_network(second.value, strict=True)
        return (
            first_network.version == second_network.version
            and first_network.overlaps(second_network)
        )
    if first.kind == RuleKind.CIDR or second.kind == RuleKind.CIDR:
        return False
    if first.kind == RuleKind.DOMAIN_REGEX and second.kind == RuleKind.DOMAIN_REGEX:
        return True
    if first.kind == RuleKind.DOMAIN_REGEX or second.kind == RuleKind.DOMAIN_REGEX:
        # A dotless-only regex provably cannot match a dotted host, so it
        # only overlaps the dotless domain grammar (see
        # ``_matches_only_dotless_hosts``); anything else stays fail-closed.
        regex_entry, other = (
            (first, second) if first.kind == RuleKind.DOMAIN_REGEX else (second, first)
        )
        if _matches_only_dotless_hosts(regex_entry.value):
            return other.kind in (
                RuleKind.DOMAIN,
                RuleKind.DOMAIN_SUFFIX,
                RuleKind.DOMAIN_KEYWORD,
                RuleKind.DOMAIN_REGEX,
            ) and "." not in other.value
        return other.kind in _DOMAIN_RULE_KINDS
    if {RuleKind.DOMAIN_KEYWORD} & {first.kind, second.kind}:
        return {first.kind, second.kind} <= _DOMAIN_RULE_KINDS
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


def _dataset_for(categorized: dict[str, tuple[RuleEntry, ...]]) -> Dataset:
    return Dataset(
        {
            category_name: Category(category_name, frozenset(entries))
            for category_name, entries in sorted(categorized.items())
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
        conflict.dataset,
        conflict.higher_category,
        conflict.lower_category,
        _entry_key(conflict.higher_entry),
        _entry_key(conflict.lower_entry),
    )
