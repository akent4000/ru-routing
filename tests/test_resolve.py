from __future__ import annotations

import ipaddress
import random
import time

import pytest

from ru_routing.config import (
    CanonicalCategoryPolicy,
    CategoryMapping,
    CategoryPolicy,
)
from ru_routing.models import Category, Dataset, PolicyTier, RuleEntry, RuleKind
from ru_routing.resolve import (
    ResolutionError,
    _build_blocker_indexes,
    _entries_overlap,
    _resolve_categories,
    _takes_ownership,
    assert_server_superset,
    resolve_datasets,
)
from ru_routing.resolve import (
    _conflicts as _indexed_conflicts,
)


def test_blocked_subdomain_removes_overlapping_lite_ru_suffix():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN_SUFFIX, "example.ru", "ru"),
            rule(RuleKind.DOMAIN, "blocked.example.ru", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == set()
    assert entries(build.lite, "blocked") == {("domain", "blocked.example.ru")}
    assert build.conflicts.overlaps_before[0].higher_category == "blocked"
    assert build.conflicts.overlaps_after == ()


def test_blocked_ipv4_subnet_splits_direct_network_without_widening():
    build = resolve_datasets(
        (
            rule(RuleKind.CIDR, "203.0.113.0/24", "ru"),
            rule(RuleKind.CIDR, "203.0.113.0/25", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    ru_entries = build.lite.categories["ru"].entries
    assert entries(build.lite, "ru") == {("cidr", "203.0.113.128/25")}
    assert next(iter(ru_entries)).sources == frozenset({"fixture"})
    assert next(iter(ru_entries)).memberships == frozenset({("fixture", "ru")})


def test_blocked_ipv6_subnet_splits_direct_network_without_widening():
    build = resolve_datasets(
        (
            rule(RuleKind.CIDR, "2001:db8::/32", "ru"),
            rule(RuleKind.CIDR, "2001:db8::/33", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == {("cidr", "2001:db8:8000::/33")}


def test_deny_precedence_removes_direct_and_blocked_duplicates():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "danger.example", "ru"),
            rule(RuleKind.DOMAIN, "danger.example", "blocked"),
            rule(RuleKind.DOMAIN, "danger.example", "spy"),
        ),
        policy_for("ru", "blocked", "spy"),
    )

    assert entries(build.lite, "ru") == set()
    assert entries(build.lite, "blocked") == set()
    assert entries(build.lite, "spy") == {("domain", "danger.example")}
    assert {
        (record.higher_category, record.lower_category)
        for record in build.conflicts.resolved
    } == {
        ("blocked", "ru"),
        ("spy", "blocked"),
        ("spy", "ru"),
    }


def test_server_keeps_thematic_membership_when_it_overlaps_trusted_direct():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "video.example", "ru"),
            rule(RuleKind.DOMAIN, "video.example", "video"),
        ),
        policy_for("ru", "video"),
    )

    assert entries(build.server, "ru") == {("domain", "video.example")}
    assert entries(build.server, "video") == {("domain", "video.example")}


def test_lite_removes_thematic_entry_that_overlaps_trusted_direct():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "video.example", "ru"),
            rule(RuleKind.DOMAIN, "video.example", "video"),
        ),
        policy_for("ru", "video"),
    )

    assert entries(build.lite, "video") == set()
    assert entries(build.server, "video") == {("domain", "video.example")}
    assert {
        (record.higher_category, record.lower_category, record.dataset)
        for record in build.conflicts.resolved
    } == {("ru", "video", "lite")}


def test_blocked_regex_removes_potentially_matching_direct_exact_and_is_reported():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "api.example.ru", "ru"),
            rule(RuleKind.DOMAIN_REGEX, r"^api\.example\.ru$", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == set()
    assert {
        (record.higher_entry.kind, record.lower_entry.kind)
        for record in build.conflicts.resolved
    } == {(RuleKind.DOMAIN_REGEX, RuleKind.DOMAIN)}


def test_dotless_regex_blocker_keeps_dotted_lower_tier_entries():
    """A regex that cannot match any dotted host must only block dotless hosts.

    Upstream geosite ``private`` ships ``^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$``,
    which matches exactly the dotless-host grammar.  Fail-closed treatment of
    that blocker wiped every dotted entry from lower-tier lite categories
    (live: lite:trackers 408 -> 0), so the overlap check must prove a dotted
    candidate can actually match before subtracting it.
    """

    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "rarbg.com", "trackers"),
            rule(RuleKind.DOMAIN_SUFFIX, "rarbg.com", "trackers"),
            rule(RuleKind.DOMAIN, "localhost", "trackers"),
            rule(
                RuleKind.DOMAIN_REGEX,
                r"^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$",
                "ru",
            ),
        ),
        policy_for("ru", "trackers"),
    )

    assert entries(build.lite, "trackers") == {
        ("domain", "rarbg.com"),
        ("domain_suffix", "rarbg.com"),
    }
    # server keeps thematic categories intact by design (_takes_ownership's
    # server+thematic carve-out), so the dotless localhost survives there.
    assert entries(build.server, "trackers") == {
        ("domain", "rarbg.com"),
        ("domain_suffix", "rarbg.com"),
        ("domain", "localhost"),
    }
    assert {
        (record.lower_entry.value, record.dataset)
        for record in build.conflicts.resolved
    } == {("localhost", "lite")}


def test_exact_blocker_removes_potentially_matching_direct_regex():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN_REGEX, r"^api\.example\.ru$", "ru"),
            rule(RuleKind.DOMAIN, "api.example.ru", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == set()
    assert build.conflicts.unresolved == ()


def test_blocked_regex_removes_broader_direct_suffix_when_holes_are_unrepresentable():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN_SUFFIX, "example.ru", "ru"),
            rule(RuleKind.DOMAIN_REGEX, r"^blocked\.example\.ru$", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == set()
    assert build.conflicts.unresolved == ()


def test_blocked_suffix_removes_broader_direct_suffix_when_holes_are_unrepresentable():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN_SUFFIX, "example.ru", "ru"),
            rule(RuleKind.DOMAIN_SUFFIX, "blocked.example.ru", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == set()
    assert build.conflicts.unresolved == ()


def test_broader_blocked_suffix_removes_contained_direct_exact():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "api.example.ru", "ru"),
            rule(RuleKind.DOMAIN_SUFFIX, "example.ru", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == set()


@pytest.mark.parametrize(
    ("higher_kind", "higher_value", "lower_kind", "lower_value"),
    [
        (RuleKind.DOMAIN_KEYWORD, "example", RuleKind.DOMAIN, "api.example.ru"),
        (RuleKind.DOMAIN_KEYWORD, "example", RuleKind.DOMAIN_SUFFIX, "example.ru"),
        (RuleKind.DOMAIN_KEYWORD, "example", RuleKind.DOMAIN_KEYWORD, "example"),
        (RuleKind.DOMAIN, "api.example.ru", RuleKind.DOMAIN_KEYWORD, "example"),
        (RuleKind.DOMAIN_SUFFIX, "example.ru", RuleKind.DOMAIN_KEYWORD, "example"),
    ],
)
def test_keyword_cross_kind_conflicts_fail_closed_and_are_reported(
    higher_kind, higher_value, lower_kind, lower_value
):
    build = resolve_datasets(
        (
            rule(lower_kind, lower_value, "ru"),
            rule(higher_kind, higher_value, "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == set()
    assert {
        (record.higher_entry.kind, record.lower_entry.kind)
        for record in build.conflicts.resolved
    } == {(higher_kind, lower_kind)}


def test_multiple_disjoint_blockers_split_one_direct_network_without_widening():
    build = resolve_datasets(
        (
            rule(RuleKind.CIDR, "203.0.113.0/24", "ru"),
            rule(RuleKind.CIDR, "203.0.113.0/26", "blocked"),
            rule(RuleKind.CIDR, "203.0.113.128/26", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == {
        ("cidr", "203.0.113.64/26"),
        ("cidr", "203.0.113.192/26"),
    }


@pytest.mark.parametrize(
    ("direct", "same_family_blocker", "other_family_blocker", "expected"),
    [
        (
            "203.0.113.0/24",
            "203.0.113.0/25",
            "2001:db8::/32",
            {("cidr", "203.0.113.128/25")},
        ),
        (
            "2001:db8::/32",
            "2001:db8::/33",
            "203.0.113.0/24",
            {("cidr", "2001:db8:8000::/33")},
        ),
    ],
)
def test_mixed_ip_family_blocker_sequence_ignores_the_other_family(
    direct, same_family_blocker, other_family_blocker, expected
):
    build = resolve_datasets(
        (
            rule(RuleKind.CIDR, direct, "ru"),
            rule(RuleKind.CIDR, same_family_blocker, "blocked"),
            rule(RuleKind.CIDR, other_family_blocker, "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == expected


@pytest.mark.parametrize("higher_category", ["blocked", "spy"])
def test_higher_precedence_category_removes_lite_thematic_but_server_keeps_it(
    higher_category,
):
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "video.example", "video"),
            rule(RuleKind.DOMAIN, "video.example", higher_category),
        ),
        policy_for("video", higher_category),
    )

    assert entries(build.lite, "video") == set()
    assert entries(build.server, "video") == {("domain", "video.example")}


def test_server_is_a_per_shared_category_superset_of_lite():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "example.ru", "ru"),
            rule(RuleKind.DOMAIN, "blocked.example.ru", "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert_server_superset(build.lite, build.server)
    assert entries(build.server, "ru") == entries(build.lite, "ru")
    assert entries(build.server, "blocked") == entries(build.lite, "blocked")


def test_resolver_produces_a_strict_server_superset_for_shared_thematic_category():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "video.example", "ru"),
            rule(RuleKind.DOMAIN, "video.example", "video"),
        ),
        policy_for("ru", "video"),
    )

    assert_server_superset(build.lite, build.server)
    assert (
        build.lite.categories["video"].entries
        < build.server.categories["video"].entries
    )


def test_mapping_membership_datasets_control_lite_and_server_category_entries():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "video.example", "ru", source="direct"),
            rule(RuleKind.DOMAIN, "video.example", "video", source="service"),
        ),
        policy_with_membership_datasets(
            {
                ("direct", "ru"): ("ru", PolicyTier.TRUSTED_DIRECT, {"lite", "server"}),
                ("service", "video"): ("video", PolicyTier.THEMATIC, {"server"}),
            }
        ),
    )

    assert "video" not in build.lite.categories
    assert entries(build.server, "video") == {("domain", "video.example")}


def test_server_only_blocker_still_subtracts_from_a_lite_published_category():
    """A higher-tier category absent from lite's `datasets:` scope (e.g.
    `blocked` is server-only) must still take conflict-resolution ownership
    over a lower-tier category that IS published in lite (`ru`) -- not just
    over categories published in the same dataset as the blocker. Dropping
    this would make lite's resolved `ru` a strict superset of server's
    resolved `ru` (server still subtracts `blocked` from its own `ru`),
    violating assert_server_superset. Regression test for that bug."""

    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "danger.example", "ru", source="direct"),
            rule(RuleKind.DOMAIN, "danger.example", "blocked", source="blocklist"),
        ),
        policy_with_membership_datasets(
            {
                ("direct", "ru"): ("ru", PolicyTier.TRUSTED_DIRECT, {"lite", "server"}),
                ("blocklist", "blocked"): (
                    "blocked",
                    PolicyTier.EXPLICIT_BLOCKED,
                    {"server"},
                ),
            }
        ),
    )

    assert "blocked" not in build.lite.categories
    assert entries(build.lite, "ru") == set()
    assert entries(build.server, "ru") == set()
    # No AnomalyError-triggering surprise: this call already ran inside
    # resolve_datasets and raising ResolutionError would have failed the
    # test above it, but assert explicitly for clarity/documentation.
    assert_server_superset(build.lite, build.server)


def test_resolver_rejects_shared_category_missing_a_lite_entry_on_server():
    policy = policy_with_membership_datasets(
        {
            ("lite-source", "ru-lite"): (
                "ru",
                PolicyTier.TRUSTED_DIRECT,
                {"lite"},
            ),
            ("server-source", "ru-server"): (
                "ru",
                PolicyTier.TRUSTED_DIRECT,
                {"server"},
            ),
        }
    )

    with pytest.raises(ResolutionError, match="server category ru"):
        resolve_datasets(
            (
                rule(RuleKind.DOMAIN, "lite.example", "ru-lite", source="lite-source"),
                rule(
                    RuleKind.DOMAIN,
                    "server.example",
                    "ru-server",
                    source="server-source",
                ),
            ),
            policy,
        )


@pytest.mark.parametrize(
    ("direct", "blocker", "expected"),
    [
        ("203.0.113.0/25", "203.0.113.0/24", set()),
        ("2001:db8:1::/48", "2001:db8::/32", set()),
    ],
)
def test_containing_blocker_removes_entire_ipv4_or_ipv6_direct_network(
    direct, blocker, expected
):
    build = resolve_datasets(
        (
            rule(RuleKind.CIDR, direct, "ru"),
            rule(RuleKind.CIDR, blocker, "blocked"),
        ),
        policy_for("ru", "blocked"),
    )

    assert entries(build.lite, "ru") == expected


def test_server_superset_check_rejects_a_missing_shared_entry():
    entry = rule(RuleKind.DOMAIN, "example.ru", "ru")
    lite = Dataset({"ru": Category("ru", frozenset({entry}))})
    server = Dataset({"ru": Category("ru", frozenset())})

    with pytest.raises(ResolutionError, match="server category ru"):
        assert_server_superset(lite, server)


def test_categories_are_emitted_in_deterministic_order():
    build = resolve_datasets(
        (
            rule(RuleKind.DOMAIN, "z.example", "zeta"),
            rule(RuleKind.DOMAIN, "a.example", "alpha"),
        ),
        policy_for("zeta", "alpha"),
    )

    assert tuple(build.lite.categories) == ("alpha", "zeta")
    assert (
        build.lite.to_canonical_json()
        == resolve_datasets(
            tuple(
                reversed(
                    (
                        rule(RuleKind.DOMAIN, "z.example", "zeta"),
                        rule(RuleKind.DOMAIN, "a.example", "alpha"),
                    )
                )
            ),
            policy_for("zeta", "alpha"),
        ).lite.to_canonical_json()
    )


def test_resolver_uses_source_category_memberships_for_canonical_mapping():
    rule_with_two_memberships = RuleEntry(
        kind=RuleKind.DOMAIN,
        value="example.ru",
        sources=frozenset({"source-a", "source-b"}),
        memberships=frozenset({("source-a", "first"), ("source-b", "second")}),
    )
    policy = CategoryPolicy(
        source_categories={
            "source-a:first": CategoryMapping(
                "source-a",
                "first",
                "alpha",
                frozenset({"lite", "server"}),
                PolicyTier.THEMATIC,
            ),
            "source-b:second": CategoryMapping(
                "source-b",
                "second",
                "beta",
                frozenset({"lite", "server"}),
                PolicyTier.THEMATIC,
            ),
        },
        canonical_categories={
            name: CanonicalCategoryPolicy(
                name, frozenset({"lite", "server"}), PolicyTier.THEMATIC
            )
            for name in ("alpha", "beta")
        },
    )

    build = resolve_datasets((rule_with_two_memberships,), policy)

    assert build.lite.categories["alpha"].entries == frozenset(
        {
            RuleEntry(
                RuleKind.DOMAIN,
                "example.ru",
                frozenset({"source-a"}),
                memberships=frozenset({("source-a", "first")}),
            )
        }
    )
    assert build.lite.categories["beta"].entries == frozenset(
        {
            RuleEntry(
                RuleKind.DOMAIN,
                "example.ru",
                frozenset({"source-b"}),
                memberships=frozenset({("source-b", "second")}),
            )
        }
    )


def policy_for(*categories: str) -> CategoryPolicy:
    tiers = {
        "blocked": PolicyTier.EXPLICIT_BLOCKED,
        "spy": PolicyTier.DENY,
        "ru": PolicyTier.TRUSTED_DIRECT,
    }
    source_categories = {
        f"fixture:{category}": CategoryMapping(
            source="fixture",
            source_category=category,
            canonical_category=category,
            datasets=frozenset({"lite", "server"}),
            tier=tiers.get(category, PolicyTier.THEMATIC),
        )
        for category in categories
    }
    canonical_categories = {
        category: CanonicalCategoryPolicy(
            name=category,
            datasets=frozenset({"lite", "server"}),
            tier=tiers.get(category, PolicyTier.THEMATIC),
        )
        for category in categories
    }
    return CategoryPolicy(source_categories, canonical_categories)


def policy_with_membership_datasets(
    definitions: dict[tuple[str, str], tuple[str, PolicyTier, set[str]]],
) -> CategoryPolicy:
    source_categories = {
        f"{source}:{source_category}": CategoryMapping(
            source,
            source_category,
            canonical_category,
            frozenset(datasets),
            tier,
        )
        for (source, source_category), (
            canonical_category,
            tier,
            datasets,
        ) in definitions.items()
    }
    canonical_categories = {
        canonical_category: CanonicalCategoryPolicy(
            canonical_category,
            frozenset({"lite", "server"}),
            tier,
        )
        for canonical_category, tier, _ in definitions.values()
    }
    return CategoryPolicy(source_categories, canonical_categories)


def rule(
    kind: RuleKind, value: str, category: str, *, source: str = "fixture"
) -> RuleEntry:
    return RuleEntry(
        kind=kind,
        value=value,
        sources=frozenset({source}),
        memberships=frozenset({(source, category)}),
    )


def entries(dataset: Dataset, category: str) -> set[tuple[str, str]]:
    return {
        (entry.kind.value, entry.value)
        for entry in dataset.categories[category].entries
    }


# --- Differential test: indexed resolution vs. a plain pairwise reference ---
#
# The indexed _resolve_categories/_conflicts in resolve.py must produce
# exactly the same result as a naive O(N*M) pairwise scan using the
# original _entries_overlap/_takes_ownership primitives (still present in
# resolve.py, kept as the semantic reference). Hand-written fixtures above
# cover every documented overlap rule individually; this generates random
# combinations to catch interaction bugs (e.g. the suffix-trie's symmetric
# containment) that fixed examples might miss.


def _reference_resolve_categories(
    dataset: str,
    categorized: dict[str, tuple[RuleEntry, ...]],
    tiers: dict[str, PolicyTier],
) -> dict[str, tuple[RuleEntry, ...]]:
    """Naive pairwise reimplementation of the pre-index _resolve_categories."""

    resolved: dict[str, tuple[RuleEntry, ...]] = {}
    for category, category_entries in categorized.items():
        tier = tiers[category]
        blockers = tuple(
            blocker
            for blocker_category, blocker_entries in categorized.items()
            if _takes_ownership(dataset, tiers[blocker_category], tier)
            for blocker in blocker_entries
        )
        kept = []
        for entry in category_entries:
            if entry.kind == RuleKind.CIDR:
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
                kept.extend(
                    RuleEntry(
                        kind=RuleKind.CIDR,
                        value=str(network),
                        sources=entry.sources,
                        attributes=entry.attributes,
                        memberships=entry.memberships,
                    )
                    for network in remaining
                )
            elif not any(_entries_overlap(entry, blocker) for blocker in blockers):
                kept.append(entry)
        resolved[category] = tuple(kept)
    return resolved


def _reference_conflicts(
    dataset: str,
    categorized: dict[str, tuple[RuleEntry, ...]],
    tiers: dict[str, PolicyTier],
) -> set[tuple[str, str, str, str, str, str, str]]:
    pairs = set()
    for higher_category, higher_entries in categorized.items():
        for lower_category, lower_entries in categorized.items():
            if not _takes_ownership(
                dataset, tiers[higher_category], tiers[lower_category]
            ):
                continue
            for higher_entry in higher_entries:
                for lower_entry in lower_entries:
                    if _entries_overlap(higher_entry, lower_entry):
                        pairs.add(
                            (
                                dataset,
                                higher_category,
                                lower_category,
                                higher_entry.kind.value,
                                higher_entry.value,
                                lower_entry.kind.value,
                                lower_entry.value,
                            )
                        )
    return pairs


def _random_entries(rng: random.Random, count: int) -> list[RuleEntry]:
    tlds = ["ru", "com", "org"]
    entries_list = []
    for i in range(count):
        choice = rng.random()
        if choice < 0.4:
            depth = rng.randint(1, 3)
            labels = [f"label{rng.randint(0, 12)}" for _ in range(depth)]
            value = ".".join([*labels, rng.choice(tlds)])
            kind = RuleKind.DOMAIN
        elif choice < 0.75:
            depth = rng.randint(0, 2)
            labels = [f"label{rng.randint(0, 12)}" for _ in range(depth)]
            tld = rng.choice(tlds)
            value = ".".join([*labels, tld]) if labels else tld
            kind = RuleKind.DOMAIN_SUFFIX
        elif choice < 0.85:
            octet = rng.randint(0, 254)
            prefix = rng.choice([24, 25, 26, 28])
            value = f"10.{rng.randint(0,3)}.{octet}.0/{prefix}"
            kind = RuleKind.CIDR
        elif choice < 0.93:
            value = f"kw{rng.randint(0, 3)}"
            kind = RuleKind.DOMAIN_KEYWORD
        else:
            value = f"re{rng.randint(0, 3)}"
            kind = RuleKind.DOMAIN_REGEX
        entries_list.append(
            RuleEntry(
                kind=kind,
                value=value,
                sources=frozenset({"fixture"}),
                memberships=frozenset({("fixture", f"cat{i % 5}")}),
            )
        )
    return entries_list


def test_indexed_resolution_matches_pairwise_reference_on_random_data():
    rng = random.Random(1234)
    tiers = {
        "cat0": PolicyTier.DENY,
        "cat1": PolicyTier.EXPLICIT_BLOCKED,
        "cat2": PolicyTier.TRUSTED_DIRECT,
        "cat3": PolicyTier.THEMATIC,
        "cat4": PolicyTier.THEMATIC,
    }
    for dataset in ("lite", "server"):
        categorized: dict[str, tuple[RuleEntry, ...]] = {}
        for i in range(5):
            category = f"cat{i}"
            categorized[category] = tuple(_random_entries(rng, 40))

        indexes = _build_blocker_indexes(dataset, categorized, categorized, tiers)

        expected_resolved = _reference_resolve_categories(dataset, categorized, tiers)
        actual_resolved = _resolve_categories(categorized, indexes)
        for category in categorized:
            assert set(actual_resolved[category]) == set(
                expected_resolved[category]
            ), f"dataset={dataset} category={category}"

        expected_conflicts = _reference_conflicts(dataset, categorized, tiers)
        actual_conflicts = {
            (
                conflict.dataset,
                conflict.higher_category,
                conflict.lower_category,
                conflict.higher_entry.kind.value,
                conflict.higher_entry.value,
                conflict.lower_entry.kind.value,
                conflict.lower_entry.value,
            )
            for conflict in _indexed_conflicts(dataset, categorized, indexes)
        }
        assert actual_conflicts == expected_conflicts, f"dataset={dataset}"


def test_indexed_cidr_conflicts_match_pairwise_reference_on_random_data():
    """CIDR conflict-pair emission uses a sorted interval index
    (_cidr_overlapping_blockers) instead of a full pairwise scan -- verify
    it finds exactly the same overlapping pairs as the reference for a
    CIDR-heavy random dataset (IPv4 and IPv6, varied prefix lengths)."""

    rng = random.Random(2024)
    tiers = {
        "cat0": PolicyTier.DENY,
        "cat1": PolicyTier.EXPLICIT_BLOCKED,
        "cat2": PolicyTier.TRUSTED_DIRECT,
        "cat3": PolicyTier.THEMATIC,
    }

    def random_cidrs(rng: random.Random, count: int) -> list[RuleEntry]:
        result = []
        for i in range(count):
            if rng.random() < 0.7:
                block = rng.randint(0, 8)
                octet = rng.randint(0, 254)
                prefix = rng.choice([12, 16, 20, 24, 25, 26, 28, 30, 32])
                address = f"10.{block}.{octet}.0/{prefix}"
                net = ipaddress.ip_network(address, strict=False)
            else:
                block = rng.randint(0, 8)
                prefix = rng.choice([32, 48, 56, 64, 96, 112])
                net = ipaddress.ip_network(f"2001:db8:{block}::/{prefix}", strict=False)
            result.append(
                RuleEntry(
                    kind=RuleKind.CIDR,
                    value=str(net),
                    sources=frozenset({"fixture"}),
                    memberships=frozenset({("fixture", f"cat{i % 4}")}),
                )
            )
        return result

    for dataset in ("lite", "server"):
        categorized: dict[str, tuple[RuleEntry, ...]] = {
            f"cat{i}": tuple(random_cidrs(rng, 200)) for i in range(4)
        }
        indexes = _build_blocker_indexes(dataset, categorized, categorized, tiers)

        expected = set()
        for hc, hes in categorized.items():
            for lc, les in categorized.items():
                if not _takes_ownership(dataset, tiers[hc], tiers[lc]):
                    continue
                for he in hes:
                    for le in les:
                        if _entries_overlap(he, le):
                            expected.add((hc, lc, he.value, le.value))

        actual = {
            (
                c.higher_category,
                c.lower_category,
                c.higher_entry.value,
                c.lower_entry.value,
            )
            for c in _indexed_conflicts(dataset, categorized, indexes)
        }
        assert actual == expected, f"dataset={dataset}"


def test_resolve_datasets_handles_a_moderately_large_synthetic_dataset_quickly():
    rng = random.Random(99)
    policy = policy_for("blocked", "spy", "ru", "thematic-a", "thematic-b")

    rules = []
    for i in range(40_000):
        rng_choice = rng.random()
        if rng_choice < 0.5:
            category = rng.choice(["blocked", "ru", "thematic-a", "thematic-b"])
        elif rng_choice < 0.7:
            category = "spy"
        else:
            category = "blocked"
        depth = rng.randint(1, 3)
        labels = [f"l{rng.randint(0, 500)}" for _ in range(depth)]
        tld = rng.choice(["ru", "com", "org"])
        value = ".".join([*labels, tld])
        kind = RuleKind.DOMAIN if rng.random() < 0.6 else RuleKind.DOMAIN_SUFFIX
        rules.append(rule(kind, value, category))

    started = time.monotonic()
    build = resolve_datasets(tuple(rules), policy)
    elapsed = time.monotonic() - started

    assert elapsed < 15.0, f"resolve_datasets took {elapsed:.2f}s for 40k rules"
    assert build.lite.categories
