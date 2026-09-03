from pathlib import Path

import pytest

import ru_routing.parsers as parsers
from ru_routing.config import FreshnessRule, LicenseMetadata, SourceDefinition
from ru_routing.models import RuleKind
from ru_routing.parsers import GeodataRule, ParseError, parse_source

FIXTURES = Path(__file__).parent / "fixtures" / "upstreams"


def _varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _protobuf_varint(field: int, value: int) -> bytes:
    return _varint(field << 3) + _varint(value)


def _protobuf_bytes(field: int, value: bytes | str) -> bytes:
    body = value.encode() if isinstance(value, str) else value
    return _varint((field << 3) | 2) + _varint(len(body)) + body


def _attribute(key: str) -> bytes:
    return _protobuf_bytes(1, key) + _protobuf_varint(2, 1)


def _domain(kind: int, value: str, *attributes: str) -> bytes:
    return (
        _protobuf_varint(1, kind)
        + _protobuf_bytes(2, value)
        + b"".join(_protobuf_bytes(3, _attribute(item)) for item in attributes)
    )


def _geosite(category: str, *domains: bytes) -> bytes:
    body = _protobuf_bytes(1, category) + b"".join(
        _protobuf_bytes(2, domain) for domain in domains
    )
    return _protobuf_bytes(1, body)


def _cidr(address: bytes, prefix: int) -> bytes:
    return _protobuf_bytes(1, address) + _protobuf_varint(2, prefix)


def _geoip(category: str, *cidrs: bytes) -> bytes:
    body = _protobuf_bytes(1, category) + b"".join(
        _protobuf_bytes(2, cidr) for cidr in cidrs
    )
    return _protobuf_bytes(1, body)


def source(
    *,
    name="fixture/source",
    input_type="plain_text",
    layout="per_category_urls",
    categories=("rules",),
    bare_domain_kind=RuleKind.DOMAIN,
):
    return SourceDefinition(
        name=name,
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
        bare_domain_kind=bare_domain_kind,
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


def test_parse_source_uses_source_bare_domain_kind_for_plain_hostnames(tmp_path):
    path = tmp_path / "rules.txt"
    path.write_text("ozon.ru\n", encoding="utf-8")

    rules = tuple(
        parse_source(
            source(bare_domain_kind=RuleKind.DOMAIN_SUFFIX), {"rules": (path,)}
        )
    )

    assert [(rule.kind, rule.value) for rule in rules] == [
        (RuleKind.DOMAIN_SUFFIX, "ozon.ru")
    ]


def test_parse_source_extracts_russian_university_domain_suffixes():
    artifact = (
        FIXTURES
        / "registry"
        / "Hipo_university-domains-list--ru.json"
    )
    hipo_source = source(
        name="Hipo/university-domains-list",
        input_type="university_domains_json",
        layout="single_artifact",
        categories=("ru",),
    )

    rules = tuple(parse_source(hipo_source, {"ru": (artifact,)}))

    assert [(rule.kind, rule.value) for rule in rules] == [
        (RuleKind.DOMAIN_SUFFIX, "mirea.ru"),
        (RuleKind.DOMAIN_SUFFIX, "msu.ru"),
    ]
    assert {rule.source for rule in rules} == {"Hipo/university-domains-list"}
    assert all(rule.category == "ru" and rule.line is None for rule in rules)


@pytest.mark.parametrize(
    ("contents", "match"),
    [
        (b'{"alpha_two_code":"RU"}', "top-level JSON value must be a list"),
        (b'["not a record"]', "record must be a mapping"),
        (
            b'[{"alpha_two_code":"RU","domains":"mirea.ru"}]',
            "domains must be a list",
        ),
        (
            b'[{"alpha_two_code":"RU","domains":[""]}]',
            "domain must be a non-empty string",
        ),
        (
            b'[{"alpha_two_code":"RU","domains":[42]}]',
            "domain must be a non-empty string",
        ),
        (b"\xff", "input is not UTF-8"),
        (b"not JSON", "invalid JSON"),
    ],
)
def test_parse_source_rejects_malformed_university_json_with_source_and_path(
    tmp_path, contents, match
):
    artifact = tmp_path / "universities.json"
    artifact.write_bytes(contents)
    hipo_source = source(
        input_type="university_domains_json",
        layout="single_artifact",
        categories=("ru",),
    )

    with pytest.raises(
        ParseError, match=rf"fixture/source.*universities.json.*{match}"
    ):
        tuple(parse_source(hipo_source, {"ru": (artifact,)}))


def test_parse_source_uses_domain_suffixes_for_the_local_university_overlay():
    overlay = (
        FIXTURES
        / "registry"
        / "local_universities-ru-overlay--ru.lst"
    )
    overlay_source = source(
        input_type="local_text",
        layout="repository_file",
        categories=("ru",),
    )

    rules = tuple(parse_source(overlay_source, {"ru": (overlay,)}))

    assert [(rule.kind, rule.value) for rule in rules] == [
        (RuleKind.DOMAIN_SUFFIX, "spbstu.ru"),
    ]
    assert {(rule.source, rule.category) for rule in rules} == {
        ("fixture/source", "ru"),
    }


def test_parse_source_rejects_non_repository_file_local_text_layout(tmp_path):
    artifact = tmp_path / "universities.txt"
    artifact.write_text("spbstu.ru\n", encoding="utf-8")
    overlay_source = source(
        input_type="local_text",
        layout="per_category_urls",
        categories=("ru",),
    )

    with pytest.raises(
        ParseError, match="fixture/source.*invalid local-text source layout"
    ):
        tuple(parse_source(overlay_source, {"ru": (artifact,)}))


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


def test_protobuf_geodata_reader_decodes_geosite_kinds_and_attributes(tmp_path):
    artifact = tmp_path / "geosite.dat"
    artifact.write_bytes(
        _geosite(
            "CATEGORY-RU",
            _domain(0, "needle", "ads"),
            _domain(1, r"^api\.example$"),
            _domain(2, "suffix.example", "trusted", "ru"),
            _domain(3, "exact.example"),
        )
    )

    rules = tuple(
        parsers.ProtobufGeodataReader().read(
            "geosite_dat", "category-ru", artifact
        )
    )

    assert [(rule.kind, rule.value, rule.attributes) for rule in rules] == [
        (RuleKind.DOMAIN_KEYWORD, "needle", frozenset({"ads"})),
        (RuleKind.DOMAIN_REGEX, r"^api\.example$", frozenset()),
        (
            RuleKind.DOMAIN_SUFFIX,
            "suffix.example",
            frozenset({"ru", "trusted"}),
        ),
        (RuleKind.DOMAIN, "exact.example", frozenset()),
    ]


def test_protobuf_geodata_reader_decodes_geoip_v4_and_v6(tmp_path):
    artifact = tmp_path / "geoip.dat"
    artifact.write_bytes(
        _geoip(
            "GEOIP-RU",
            _cidr(bytes([203, 0, 113, 0]), 24),
            _cidr(bytes.fromhex("20010db8000000000000000000000000"), 32),
        )
    )

    rules = tuple(
        parsers.ProtobufGeodataReader().read("geoip_dat", "geoip-ru", artifact)
    )

    assert [(rule.kind, rule.value) for rule in rules] == [
        (RuleKind.CIDR, "203.0.113.0/24"),
        (RuleKind.CIDR, "2001:db8::/32"),
    ]


def test_protobuf_geodata_reader_rejects_inverse_geoip_categories(tmp_path):
    artifact = tmp_path / "geoip.dat"
    category = (
        _protobuf_bytes(1, "RU")
        + _protobuf_bytes(2, _cidr(bytes([203, 0, 113, 0]), 24))
        + _protobuf_varint(3, 1)
    )
    artifact.write_bytes(_protobuf_bytes(1, category))

    with pytest.raises(ParseError, match=r"inverse-match"):
        tuple(parsers.ProtobufGeodataReader().read("geoip_dat", "ru", artifact))


def test_protobuf_geodata_reader_rejects_absent_category(tmp_path):
    artifact = tmp_path / "geosite.dat"
    artifact.write_bytes(_geosite("OTHER", _domain(3, "other.example")))

    with pytest.raises(ParseError, match=r"category-ru.*not found"):
        tuple(
            parsers.ProtobufGeodataReader().read(
                "geosite_dat", "category-ru", artifact
            )
        )


def test_protobuf_geodata_reader_uses_one_artifact_snapshot_for_all_categories(
    tmp_path,
):
    artifact = tmp_path / "geosite.dat"
    artifact.write_bytes(
        _geosite("ONE", _domain(3, "one.example"))
        + _geosite("TWO", _domain(3, "two.example"))
    )
    reader = parsers.ProtobufGeodataReader()

    assert [rule.value for rule in reader.read("geosite_dat", "one", artifact)] == [
        "one.example"
    ]
    artifact.write_bytes(_geosite("ONE", _domain(3, "changed.example")))

    assert [rule.value for rule in reader.read("geosite_dat", "two", artifact)] == [
        "two.example"
    ]


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
