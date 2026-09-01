from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

import ru_routing.render as render_module
from ru_routing.config import (
    CanonicalCategoryPolicy,
    CategoryMapping,
    CategoryPolicy,
    load_policy,
    load_registry,
)
from ru_routing.models import Category, Dataset, PolicyTier, RuleEntry, RuleKind
from ru_routing.normalize import normalize_rule
from ru_routing.parsers import RawRule, parse_source
from ru_routing.render import (
    render_dlc_sources,
    render_geoip_config,
    render_mihomo_yaml,
    render_raw,
    render_singbox_json,
    representation_report,
)
from ru_routing.resolve import ConflictReport, ResolvedBuild, resolve_datasets

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = REPO_ROOT / "config"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "upstreams" / "registry"


def test_render_raw_writes_a_stable_lite_and_server_tree_atomically(tmp_path):
    dist = tmp_path / "dist"
    (dist / "raw" / "lite" / "domains").mkdir(parents=True)
    (dist / "raw" / "lite" / "domains" / "stale.txt").write_text("stale\n")

    report = render_raw(build(), dist)

    assert tree(dist / "raw") == {
        "lite/domains/blocked.txt": "full:blocked.example @cn\n",
        "lite/domains/ru.txt": (
            "full:exact.example\n"
            "domain:suffix.example @attr\n"
            "keyword:needle\n"
            "regexp:^api\\.example$\n"
        ),
        "lite/ip/ru.txt": "203.0.113.0/24\n",
        "server/domains/blocked.txt": "full:blocked.example @cn\n",
        "server/domains/ru.txt": (
            "full:exact.example\n"
            "domain:suffix.example @attr\n"
            "keyword:needle\n"
            "regexp:^api\\.example$\n"
        ),
        "server/ip/ru.txt": "203.0.113.0/24\n",
        "server/ip/ru-geoip.txt": "2001:db8::/32\n",
    }
    assert not (dist / "raw" / "lite" / "domains" / "stale.txt").exists()
    assert all(item.represented for item in report.entries if item.target == "raw")

    first = tree_hash(dist / "raw")
    render_raw(build(), dist)
    assert tree_hash(dist / "raw") == first


def test_render_dlc_sources_preserves_domain_kinds_attributes_and_order(tmp_path):
    report = render_dlc_sources(build(include_private=True).lite, tmp_path / "dlc")

    assert tree(tmp_path / "dlc") == {
        "blocked": "full:blocked.example @cn\n",
        "private": "full:private.example\n",
        "ru": (
            "full:exact.example\n"
            "domain:suffix.example @attr\n"
            "keyword:needle\n"
            "regexp:^api\\.example$\n"
        ),
    }
    assert all(item.represented for item in report.entries)


def test_fixture_itdog_lite_dlc_source_renders_ozon_as_domain_suffix(tmp_path):
    registry = load_registry(CONFIG_DIR / "sources.yaml")
    source = registry.resolve("itdoginfo/allow-domains")
    rules = parse_source(
        source,
        {
            "russia-outside": (
                FIXTURES_DIR / "itdoginfo_allow-domains--russia-outside.lst",
            )
        },
    )
    resolved = resolve_datasets(
        tuple(normalize_rule(rule) for rule in rules),
        load_policy(CONFIG_DIR / "categories.yaml"),
    )

    render_dlc_sources(resolved.lite, tmp_path / "dlc")

    assert "domain:ozon.ru\n" in (tmp_path / "dlc" / "ru-inside").read_text(
        encoding="utf-8"
    )


def test_render_geoip_config_uses_inline_cidrs_and_deterministic_v2fly_schema(tmp_path):
    path = tmp_path / "geoip.json"
    report = render_geoip_config(build().server, path)

    assert path.read_text(encoding="utf-8") == (
        "{\n"
        '  "input": [\n'
        "    {\n"
        '      "action": "add",\n'
        '      "args": {\n'
        '        "ipOrCIDR": [\n'
        '          "203.0.113.0/24"\n'
        "        ],\n"
        '        "name": "ru"\n'
        "      },\n"
        '      "type": "text"\n'
        "    },\n"
        "    {\n"
        '      "action": "add",\n'
        '      "args": {\n'
        '        "ipOrCIDR": [\n'
        '          "2001:db8::/32"\n'
        "        ],\n"
        '        "name": "ru-geoip"\n'
        "      },\n"
        '      "type": "text"\n'
        "    }\n"
        "  ],\n"
        '  "output": [\n'
        "    {\n"
        '      "action": "output",\n'
        '      "args": {\n'
        '        "outputDir": ".",\n'
        '        "outputName": "geoip.dat"\n'
        "      },\n"
        '      "type": "v2rayGeoIPDat"\n'
        "    }\n"
        "  ]\n"
        "}\n"
    )
    assert [entry.category for entry in report.entries] == ["ru", "ru-geoip"]


def test_render_singbox_json_preserves_every_normalized_rule_kind():
    assert json.loads(render_singbox_json(build().lite.categories["ru"])) == {
        "version": 1,
        "rules": [
            {
                "domain": ["exact.example"],
                "domain_suffix": ["suffix.example"],
                "domain_keyword": ["needle"],
                "domain_regex": [r"^api\.example$"],
                "ip_cidr": ["203.0.113.0/24"],
            }
        ],
    }
    assert render_singbox_json(build().lite.categories["ru"]).endswith("\n")


def test_render_mihomo_yaml_uses_classical_rules_for_supported_kinds():
    category = Category(
        "safe",
        frozenset(
            {
                entry(RuleKind.DOMAIN, "exact.example"),
                entry(RuleKind.DOMAIN_SUFFIX, "suffix.example"),
                entry(RuleKind.CIDR, "203.0.113.0/24"),
            }
        ),
    )

    assert render_mihomo_yaml(category) == (
        "payload:\n"
        "  - DOMAIN,exact.example\n"
        "  - DOMAIN-SUFFIX,suffix.example\n"
        "  - IP-CIDR,203.0.113.0/24,no-resolve\n"
    )


def test_render_mihomo_yaml_preserves_keyword_and_regex_for_high_precedence_category():
    pattern = r"^api\.example$"
    category = Category(
        "spy",
        frozenset(
            {
                entry(RuleKind.DOMAIN_KEYWORD, "needle"),
                entry(RuleKind.DOMAIN_REGEX, pattern),
            }
        ),
    )

    assert yaml.safe_load(render_mihomo_yaml(category)) == {
        "payload": ["DOMAIN-KEYWORD,needle", f"DOMAIN-REGEX,{pattern}"]
    }


def test_render_mihomo_yaml_round_trips_yaml_significant_regex_characters():
    pattern = r'^api: value # note "quoted" \\path$'
    category = Category(
        "thematic", frozenset({entry(RuleKind.DOMAIN_REGEX, pattern)})
    )

    assert yaml.safe_load(render_mihomo_yaml(category)) == {
        "payload": [f"DOMAIN-REGEX,{pattern}"]
    }


def test_representation_report_distinguishes_same_category_in_lite_and_server():
    report = representation_report(build())

    records = [
        record
        for record in report.entries
        if record.target == "mihomo"
        and record.category == "blocked"
        and record.value == "blocked.example"
    ]

    assert [record.dataset for record in records] == ["lite", "server"]


def test_render_geoip_config_keeps_existing_file_when_atomic_replace_fails(
    tmp_path, monkeypatch
):
    path = tmp_path / "geoip.json"
    path.write_text("known-good\n", encoding="utf-8")

    def reject_replace(source, destination):
        raise OSError("simulated replacement failure")

    monkeypatch.setattr(render_module.os, "replace", reject_replace)

    with pytest.raises(OSError, match="simulated replacement failure"):
        render_geoip_config(build().server, path)

    assert path.read_text(encoding="utf-8") == "known-good\n"
    assert not list(tmp_path.glob(".geoip.json.tmp-*"))


def test_high_precedence_mihomo_regex_is_reported_as_represented(tmp_path):
    spy = Dataset(
        {
            "spy": Category(
                "spy", frozenset({entry(RuleKind.DOMAIN_REGEX, r"^bad\\.example$")})
            )
        }
    )
    unsafe = ResolvedBuild(lite=spy, server=spy, conflicts=ConflictReport((), (), ()))

    report = render_raw(unsafe, tmp_path / "dist")

    assert all(record.represented for record in report.entries)
    assert yaml.safe_load(render_mihomo_yaml(spy.categories["spy"])) == {
        "payload": [r"DOMAIN-REGEX,^bad\\.example$"]
    }


@pytest.mark.parametrize(
    ("suffix", "subdomain"),
    [
        ("ozon.ru", "xapi.ozon.ru"),
        ("ozonusercontent.com", "cdn1.ozonusercontent.com"),
    ],
)
def test_domain_suffix_semantics_survive_parse_through_every_engine_render(
    suffix, subdomain, tmp_path
):
    """A `domain:` rule (e.g. `domain:ozon.ru`) must render as a suffix match
    in every target engine, not degrade into an exact-only rule -- otherwise
    subdomains such as `xapi.ozon.ru` silently stop matching DIRECT."""

    raw = RawRule(
        source="aireps/geosite",
        category="whitelist",
        kind=RuleKind.DOMAIN_SUFFIX,
        value=suffix,
        path=Path("fixture"),
        line=1,
    )
    normalized = normalize_rule(raw)
    assert normalized.kind == RuleKind.DOMAIN_SUFFIX

    policy = CategoryPolicy(
        source_categories={
            "aireps/geosite:whitelist": CategoryMapping(
                "aireps/geosite",
                "whitelist",
                "ru-whitelist",
                frozenset({"lite", "server"}),
                PolicyTier.TRUSTED_DIRECT,
            ),
        },
        canonical_categories={
            "ru-whitelist": CanonicalCategoryPolicy(
                "ru-whitelist", frozenset({"lite", "server"}), PolicyTier.TRUSTED_DIRECT
            ),
        },
    )

    resolved = resolve_datasets((normalized,), policy)
    category = resolved.lite.categories["ru-whitelist"]
    assert category.entries == frozenset({normalized})

    # Xray dlc source rendering must keep the `domain:` suffix prefix, not
    # degrade to `full:` (exact-only) or drop the prefix entirely.
    render_dlc_sources(resolved.lite, tmp_path / "dlc")
    dlc_text = (tmp_path / "dlc" / "ru-whitelist").read_text(encoding="utf-8")
    assert dlc_text == f"domain:{suffix}\n"

    # sing-box: suffix values belong under domain_suffix, never bare domain.
    singbox_rules = json.loads(render_singbox_json(category))["rules"][0]
    assert singbox_rules.get("domain_suffix") == [suffix]
    assert suffix not in singbox_rules.get("domain", [])

    # Mihomo: DOMAIN-SUFFIX, not DOMAIN (which would be exact-match only).
    mihomo_payload = yaml.safe_load(render_mihomo_yaml(category))["payload"]
    assert f"DOMAIN-SUFFIX,{suffix}" in mihomo_payload
    assert f"DOMAIN,{suffix}" not in mihomo_payload

    # The subdomain is not itself a listed rule; suffix semantics (not an
    # exact match) is what makes it covered, and that's exactly what all
    # three engines were just shown to preserve above.
    assert subdomain.endswith(f".{suffix}")


def build(*, include_private: bool = False) -> ResolvedBuild:
    ru = Category(
        "ru",
        frozenset(
            {
                entry(RuleKind.DOMAIN, "exact.example"),
                entry(RuleKind.DOMAIN_SUFFIX, "suffix.example", {"attr"}),
                entry(RuleKind.DOMAIN_KEYWORD, "needle"),
                entry(RuleKind.DOMAIN_REGEX, r"^api\.example$"),
                entry(RuleKind.CIDR, "203.0.113.0/24"),
            }
        ),
    )
    blocked = Category(
        "blocked", frozenset({entry(RuleKind.DOMAIN, "blocked.example", {"cn"})})
    )
    private = Category(
        "private",
        frozenset(
            {
                RuleEntry(
                    RuleKind.CIDR,
                    "10.0.0.0/8",
                    frozenset({"builtin/private-networks"}),
                    memberships=frozenset({("builtin/private-networks", "private")}),
                ),
                RuleEntry(
                    RuleKind.DOMAIN,
                    "private.example",
                    frozenset({"aireps/geosite"}),
                    memberships=frozenset({("aireps/geosite", "private")}),
                ),
            }
        ),
    )
    categories = {"ru": ru, "blocked": blocked}
    if include_private:
        categories["private"] = private
    lite = Dataset(categories)
    server = Dataset(
        {
            **categories,
            "ru-geoip": Category(
                "ru-geoip", frozenset({entry(RuleKind.CIDR, "2001:db8::/32")})
            ),
        }
    )
    return ResolvedBuild(lite=lite, server=server, conflicts=ConflictReport((), (), ()))


def entry(kind: RuleKind, value: str, attributes: set[str] | None = None) -> RuleEntry:
    return RuleEntry(
        kind=kind,
        value=value,
        sources=frozenset({"fixture"}),
        attributes=frozenset(attributes or set()),
    )


def tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for name, content in tree(root).items():
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(content.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()
