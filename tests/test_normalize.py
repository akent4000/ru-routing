from pathlib import Path

import pytest

from ru_routing.models import RuleEntry, RuleKind
from ru_routing.normalize import (
    NormalizationError,
    normalize_domain,
    normalize_rule,
    normalize_sources,
)
from ru_routing.parsers import RawRule


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("ПРИМЕР.РФ", "xn--e1afmkfd.xn--p1ai"),
        ("Example.COM.", "example.com"),
    ],
)
def test_normalize_domain_converts_to_canonical_ascii_idna(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", ".example.com", "example..com", "bad_domain.com"])
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
        RuleEntry(RuleKind.DOMAIN, "example.com", frozenset({"source/a", "source/z"})),
        RuleEntry(RuleKind.DOMAIN_SUFFIX, "example.com", frozenset({"source/a"})),
    )


def raw_rule(kind, value, *, source="fixture/source"):
    return RawRule(
        source=source,
        category="rules",
        kind=kind,
        value=value,
        path=Path("rules.txt"),
        line=7,
    )
