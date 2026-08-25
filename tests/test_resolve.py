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
