from pathlib import Path

import pytest

from ru_routing.config import FreshnessRule, LicenseMetadata, SourceDefinition
from ru_routing.models import RuleKind
from ru_routing.parsers import GeodataRule, ParseError, parse_source

FIXTURES = Path(__file__).parent / "fixtures" / "upstreams"


def source(
    *,
    input_type="plain_text",
    layout="per_category_urls",
    categories=("rules",),
):
    return SourceDefinition(
        name="fixture/source",
        url="https://example.test/rules",
        input_type=input_type,
        layout=layout,
        required=True,
        expected_categories=categories,
        category_locations={
            category: ("https://example.test/rules",) for category in categories
        },
        attribution="Fixture contributors",
        license=LicenseMetadata("MIT", True),
        freshness=FreshnessRule(max_age_hours=48),
    )


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
    rules = tuple(
        parse_source(source(), {"rules": (FIXTURES / fixture,)})
    )

    assert [(rule.kind, rule.value) for rule in rules] == expected
    assert {rule.source for rule in rules} == {"fixture/source"}
    assert {rule.category for rule in rules} == {"rules"}


def test_parse_source_rejects_unknown_domain_list_rule_with_source_and_line(tmp_path):
    path = tmp_path / "rules.txt"
    path.write_text("unsupported:value\n", encoding="utf-8")

    with pytest.raises(ParseError, match=r"fixture/source.*rules.txt:1.*unsupported"):
        tuple(parse_source(source(), {"rules": (path,)}))


def test_parse_source_dispatches_binary_geodata_to_an_injected_reader(tmp_path):
    artifact = tmp_path / "geoip.dat"
    artifact.write_bytes(b"\x80not-utf8")
    definition = source(
        input_type="geoip_dat",
        layout="single_artifact",
        categories=("ru", "global"),
    )
    reader = RecordingGeodataReader()

    rules = tuple(
        parse_source(
            definition,
            {"ru": (artifact,), "global": (artifact,)},
            geodata_reader=reader,
        )
    )

    assert [(rule.category, rule.kind, rule.value) for rule in rules] == [
        ("ru", RuleKind.CIDR, "203.0.113.0/24"),
        ("global", RuleKind.CIDR, "2001:db8::/32"),
    ]
    assert reader.calls == [
        ("geoip_dat", "ru", artifact),
        ("geoip_dat", "global", artifact),
    ]


def test_parse_source_rejects_binary_geodata_without_a_reader(tmp_path):
    artifact = tmp_path / "geosite.dat"
    artifact.write_bytes(b"\x80not-utf8")
    definition = source(
        input_type="geosite_dat", layout="single_artifact", categories=("ru",)
    )

    with pytest.raises(ParseError, match=r"fixture/source.*ru.*geodata reader"):
        tuple(parse_source(definition, {"ru": (artifact,)}))


def test_parse_source_rejects_an_undeclared_plain_text_layout(tmp_path):
    path = tmp_path / "rules.txt"
    path.write_text("example.com\n", encoding="utf-8")
    definition = source(layout="single_artifact")

    with pytest.raises(ParseError, match=r"fixture/source.*plain-text.*layout"):
        tuple(parse_source(definition, {"rules": (path,)}))


def test_parse_source_resolves_dlc_includes_filters_and_affiliations(tmp_path):
    base = tmp_path / "base"
    base.write_text(
        "\n".join(
            [
                "full:keep.example @ads &affiliated",
                "domain:excluded.example @ads @cn",
                "domain:plain.example",
            ]
        ),
        encoding="utf-8",
    )
    rules = tmp_path / "rules"
    rules.write_text("include:base @ads @-cn\n", encoding="utf-8")

    parsed = tuple(
        parse_source(
            source(categories=("base", "rules")),
            {"base": (base,), "rules": (rules,)},
        )
    )

    assert [
        (rule.category, rule.kind, rule.value, rule.attributes)
        for rule in parsed
        if rule.category in {"rules", "affiliated"}
    ] == [
        ("rules", RuleKind.DOMAIN, "keep.example", frozenset({"ads"})),
        ("affiliated", RuleKind.DOMAIN, "keep.example", frozenset({"ads"})),
    ]


def test_parse_source_treats_bang_prefixed_dlc_attributes_as_positive_filters(
    tmp_path,
):
    base = tmp_path / "base"
    base.write_text(
        "\n".join(
            [
                "full:literal-bang.example @!cn",
                "full:no-attribute.example",
                "full:ordinary-cn.example @cn",
            ]
        ),
        encoding="utf-8",
    )
    rules = tmp_path / "rules"
    rules.write_text("include:base @!cn\n", encoding="utf-8")

    parsed = tuple(
        parse_source(
            source(categories=("base", "rules")),
            {"base": (base,), "rules": (rules,)},
        )
    )

    assert [
        (rule.value, rule.attributes) for rule in parsed if rule.category == "rules"
    ] == [("literal-bang.example", frozenset({"!cn"}))]


def test_parse_source_resolves_includes_of_affiliated_no_file_targets(tmp_path):
    base = tmp_path / "base"
    base.write_text("full:service.example &bundle\n", encoding="utf-8")
    rules = tmp_path / "rules"
    rules.write_text("include:bundle\n", encoding="utf-8")

    parsed = tuple(
        parse_source(
            source(categories=("base", "rules")),
            {"base": (base,), "rules": (rules,)},
        )
    )

    assert [
        (rule.category, rule.value)
        for rule in parsed
        if rule.category in {"bundle", "rules"}
    ] == [("rules", "service.example"), ("bundle", "service.example")]


@pytest.mark.parametrize(
    ("contents", "match"),
    [
        ({"rules": "include:missing\n"}, r"fixture/source.*rules:1.*missing include"),
        (
            {"a": "include:b\n", "b": "include:a\n"},
            r"fixture/source.*include cycle.*a.*b",
        ),
        ({"rules": "domain:example.com @\n"}, r"fixture/source.*rules:1.*attribute"),
    ],
)
def test_parse_source_rejects_invalid_dlc_references_and_attributes(
    tmp_path, contents, match
):
    paths = {}
    for category, body in contents.items():
        path = tmp_path / category
        path.write_text(body, encoding="utf-8")
        paths[category] = (path,)

    with pytest.raises(ParseError, match=match):
        tuple(parse_source(source(categories=tuple(contents)), paths))


class RecordingGeodataReader:
    def __init__(self):
        self.calls = []

    def read(self, input_type, category, artifact):
        self.calls.append((input_type, category, artifact))
        value = "203.0.113.0/24" if category == "ru" else "2001:db8::/32"
        return (GeodataRule(RuleKind.CIDR, value),)
