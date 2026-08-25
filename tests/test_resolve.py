from __future__ import annotations

import pytest

from ru_routing.config import (
    CanonicalCategoryPolicy,
    CategoryMapping,
    CategoryPolicy,
)
from ru_routing.models import Category, Dataset, PolicyTier, RuleEntry, RuleKind
from ru_routing.resolve import ResolutionError, assert_server_superset, resolve_datasets


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
