from pathlib import Path

import pytest

from ru_routing.models import RuleKind
from ru_routing.parsers import ParseError, parse_source

FIXTURES = Path(__file__).parent / "fixtures" / "upstreams"


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        (
            "domains.txt",
            [
                (RuleKind.DOMAIN, "Example.COM."),
                (RuleKind.DOMAIN, "ПРИМЕР.РФ"),
            ],
        ),
        (
            "cidrs.txt",
            [
                (RuleKind.CIDR, "203.0.113.0/24"),
                (RuleKind.CIDR, "2001:db8::/32"),
            ],
        ),
        (
            "dlc-data.txt",
            [
                (RuleKind.DOMAIN, "exact.example"),
                (RuleKind.DOMAIN_SUFFIX, "suffix.example"),
                (RuleKind.DOMAIN_KEYWORD, "needle"),
                (RuleKind.DOMAIN_REGEX, r"^api\.example\.com$"),
            ],
        ),
    ],
)
def test_parse_source_adapts_plain_and_domain_list_rules(fixture, expected):
    rules = tuple(parse_source("fixture/source", {"rules": (FIXTURES / fixture,)}))

    assert [(rule.kind, rule.value) for rule in rules] == expected
    assert {rule.source for rule in rules} == {"fixture/source"}
    assert {rule.category for rule in rules} == {"rules"}


def test_parse_source_rejects_unknown_domain_list_rule_with_source_and_line(tmp_path):
    path = tmp_path / "rules.txt"
    path.write_text("unsupported:value\n", encoding="utf-8")

    with pytest.raises(ParseError, match=r"fixture/source.*rules.txt:1.*unsupported"):
        tuple(parse_source("fixture/source", {"rules": (path,)}))
