from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ru_routing.models import Category, Dataset, RuleEntry, RuleKind
from ru_routing.render import (
    RepresentationError,
    render_dlc_sources,
    render_geoip_config,
    render_mihomo_yaml,
    render_raw,
    render_singbox_json,
)
from ru_routing.resolve import ConflictReport, ResolvedBuild


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
    report = render_dlc_sources(build().lite, tmp_path / "dlc")

    assert tree(tmp_path / "dlc") == {
        "blocked": "full:blocked.example @cn\n",
        "ru": (
            "full:exact.example\n"
            "domain:suffix.example @attr\n"
            "keyword:needle\n"
            "regexp:^api\\.example$\n"
        ),
    }
    assert all(item.represented for item in report.entries)


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


def test_unrepresentable_high_precedence_mihomo_entry_fails_closed(tmp_path):
    spy = Dataset(
        {
            "spy": Category(
                "spy", frozenset({entry(RuleKind.DOMAIN_REGEX, r"^bad\\.example$")})
            )
        }
    )
    unsafe = ResolvedBuild(lite=spy, server=spy, conflicts=ConflictReport((), (), ()))

    with pytest.raises(RepresentationError, match="mihomo.*spy.*domain_regex"):
        render_raw(unsafe, tmp_path / "dist")


def build() -> ResolvedBuild:
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
    lite = Dataset({"ru": ru, "blocked": blocked})
    server = Dataset(
        {
            "ru": ru,
            "blocked": blocked,
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
