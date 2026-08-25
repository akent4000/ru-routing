from pathlib import Path

import pytest

from ru_routing.config import (
    FreshnessRule,
    LicenseMetadata,
    SourceDefinition,
    SourceRegistry,
)
from ru_routing.fetch import FetchedSource
from ru_routing.models import RuleEntry, RuleKind
from ru_routing.normalize import (
    TARGET_COMPATIBILITY,
    NormalizationError,
    normalize_domain,
    normalize_rule,
    normalize_sources,
)
from ru_routing.parsers import GeodataRule, RawRule


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ПРИМЕР.РФ", "xn--e1afmkfd.xn--p1ai"),
        ("Example.COM.", "example.com"),
    ],
)
def test_normalize_domain_converts_to_canonical_ascii_idna(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize(
    "raw", ["", ".example.com", "example..com", "example.com..", "bad_domain.com"]
)
def test_normalize_domain_rejects_invalid_names(raw):
    with pytest.raises(NormalizationError, match="fixture/source.*rules.txt:7"):
        normalize_rule(raw_rule(RuleKind.DOMAIN, raw))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("203.0.113.0/24", "203.0.113.0/24"),
        ("2001:0DB8:0:0::/32", "2001:db8::/32"),
    ],
)
def test_normalize_rule_canonicalizes_ipv4_and_ipv6_networks(raw, expected):
    assert normalize_rule(raw_rule(RuleKind.CIDR, raw)).value == expected


def test_normalize_rule_rejects_cidr_host_bits_when_they_are_not_a_network():
    with pytest.raises(
        NormalizationError, match="fixture/source.*rules.txt:7.*host bits"
    ):
        normalize_rule(raw_rule(RuleKind.CIDR, "203.0.113.12/24"))


def test_normalize_sources_deduplicates_rules_and_unions_provenance_deterministically():
    normalized = normalize_sources(
        [
            raw_rule(RuleKind.DOMAIN, "Example.COM.", source="source/z"),
            raw_rule(RuleKind.DOMAIN, "example.com", source="source/a"),
            raw_rule(RuleKind.DOMAIN_SUFFIX, "example.com", source="source/a"),
        ]
    )

    assert normalized == (
        RuleEntry(
            RuleKind.DOMAIN,
            "example.com",
            frozenset({"source/a", "source/z"}),
            memberships=frozenset({("source/a", "rules"), ("source/z", "rules")}),
        ),
        RuleEntry(
            RuleKind.DOMAIN_SUFFIX,
            "example.com",
            frozenset({"source/a"}),
            memberships=frozenset({("source/a", "rules")}),
        ),
    )


def test_normalize_sources_keeps_duplicate_values_in_distinct_source_categories():
    normalized = normalize_sources(
        [
            raw_rule(RuleKind.DOMAIN, "example.com", category="inside"),
            raw_rule(RuleKind.DOMAIN, "example.com", category="blocked"),
        ]
    )

    assert normalized == (
        RuleEntry(
            RuleKind.DOMAIN,
            "example.com",
            frozenset({"fixture/source"}),
            memberships=frozenset({("fixture/source", "blocked")}),
        ),
        RuleEntry(
            RuleKind.DOMAIN,
            "example.com",
            frozenset({"fixture/source"}),
            memberships=frozenset({("fixture/source", "inside")}),
        ),
    )


def test_normalize_sources_preserves_target_incompatible_rule_kinds_and_attributes():
    normalized = normalize_sources(
        [
            raw_rule(RuleKind.DOMAIN_KEYWORD, "Needle", attributes=("ads",)),
            raw_rule(RuleKind.DOMAIN_REGEX, r"^api\.example$", attributes=("ads",)),
        ]
    )

    assert [(entry.kind, entry.value, entry.attributes) for entry in normalized] == [
        (RuleKind.DOMAIN_KEYWORD, "needle", frozenset({"ads"})),
        (RuleKind.DOMAIN_REGEX, r"^api\.example$", frozenset({"ads"})),
    ]
    assert "mihomo" not in TARGET_COMPATIBILITY[RuleKind.DOMAIN_KEYWORD]
    assert "mihomo" not in TARGET_COMPATIBILITY[RuleKind.DOMAIN_REGEX]


@pytest.mark.parametrize("raw", [r"(?=api)", r"(api)\1", r"(?P<api>api)", r"\Aapi"])
def test_normalize_rule_rejects_regex_outside_conservative_re2_subset(raw):
    with pytest.raises(
        NormalizationError, match="fixture/source.*rules.txt:7.*RE2-compatible"
    ):
        normalize_rule(raw_rule(RuleKind.DOMAIN_REGEX, raw))


def test_normalize_sources_resolves_fetched_binary_source_through_the_registry(
    tmp_path,
):
    artifact = tmp_path / "geosite.dat"
    artifact.write_bytes(b"\x80binary")
    definition = source_definition("geosite_dat", ("ru",))
    fetched = FetchedSource(
        name=definition.name,
        resolved_revision="revision",
        sha256="0" * 64,
        license=definition.license,
        object_paths={"ru": (artifact,)},
        observed_freshness_lag_hours=None,
    )

    normalized = normalize_sources(
        (fetched,),
        registry=SourceRegistry((definition,)),
        geodata_reader=GeodataReader(),
    )

    assert normalized == (
        RuleEntry(
            RuleKind.DOMAIN_SUFFIX,
            "example.com",
            frozenset({"fixture/source"}),
            memberships=frozenset({("fixture/source", "ru")}),
        ),
    )


def raw_rule(kind, value, *, source="fixture/source", category="rules", attributes=()):
    return RawRule(
        source=source,
        category=category,
        kind=kind,
        value=value,
        path=Path("rules.txt"),
        line=7,
        attributes=frozenset(attributes),
    )


def source_definition(input_type, categories):
    return SourceDefinition(
        name="fixture/source",
        url="https://example.test/rules",
        input_type=input_type,
        layout="single_artifact",
        required=True,
        expected_categories=categories,
        category_locations={
            category: ("https://example.test/rules",) for category in categories
        },
        attribution="Fixture contributors",
        license=LicenseMetadata("MIT", True),
        freshness=FreshnessRule(max_age_hours=48),
    )


class GeodataReader:
    def read(self, input_type, category, artifact):
        assert input_type == "geosite_dat"
        assert category == "ru"
        return (GeodataRule(RuleKind.DOMAIN_SUFFIX, "example.com"),)
