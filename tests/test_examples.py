"""Structural, schema, and rendering tests for the engine configuration examples.

These tests deliberately do not invoke real xray/sing-box/mihomo binaries --
that native `check` validation is pinned Docker tooling introduced in Task 10.
Here we assert the committed templates' JSON/YAML are well-formed and encode
the documented lite/server policy ordering, required outbound tags, and
non-parity notes, plus that ru_routing.render.render_examples correctly
copies and substitutes them into the dist/examples output contract layout.
"""

from __future__ import annotations

import hashlib
import json
import re
import tempfile
from pathlib import Path

import pytest
import yaml

from ru_routing.config import load_policy, load_registry
from ru_routing.fetch import FetchedSource
from ru_routing.models import RuleKind, category_is_cidr_capable
from ru_routing.normalize import normalize_sources
from ru_routing.parsers import GeodataRule
from ru_routing.render import render_examples
from ru_routing.resolve import resolve_datasets

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "examples" / "templates"
CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"

REQUIRED_TAGS = {"direct", "proxy", "block", "node-example"}


def _load_json_template(name: str) -> dict:
    text = (TEMPLATES_DIR / name).read_text(encoding="utf-8")
    text = text.replace("{{VERSION}}", "2026.08.26.0000-deadbeef").replace(
        "{{CDN_BASE}}", "https://routing.akent.site/latest"
    )
    return json.loads(text)


def _load_yaml_template(name: str) -> dict:
    text = (TEMPLATES_DIR / name).read_text(encoding="utf-8")
    text = text.replace("{{VERSION}}", "2026.08.26.0000-deadbeef").replace(
        "{{CDN_BASE}}", "https://routing.akent.site/latest"
    )
    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# Templates exist and parse
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "xray-lite.json",
        "xray-server.json",
        "sing-box-lite.json",
        "sing-box-server.json",
    ],
)
def test_json_templates_are_valid_json(name):
    document = _load_json_template(name)
    assert isinstance(document, dict)


@pytest.mark.parametrize("name", ["mihomo-lite.yaml", "mihomo-server.yaml"])
def test_yaml_templates_are_valid_yaml(name):
    document = _load_yaml_template(name)
    assert isinstance(document, dict)


# ---------------------------------------------------------------------------
# Required outbound tags
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["xray-lite.json", "xray-server.json"])
def test_xray_templates_declare_required_outbound_tags(name):
    document = _load_json_template(name)
    tags = {outbound["tag"] for outbound in document["outbounds"]}
    assert REQUIRED_TAGS <= tags


@pytest.mark.parametrize("name", ["sing-box-lite.json", "sing-box-server.json"])
def test_singbox_templates_declare_required_outbound_tags(name):
    document = _load_json_template(name)
    tags = {outbound["tag"] for outbound in document["outbounds"]}
    assert REQUIRED_TAGS <= tags


@pytest.mark.parametrize("name", ["mihomo-lite.yaml", "mihomo-server.yaml"])
def test_mihomo_templates_declare_required_tags(name):
    document = _load_yaml_template(name)
    proxy_names = {proxy["name"] for proxy in document.get("proxies", [])}
    group_names = {group["name"] for group in document.get("proxy-groups", [])}
    rule_text = "\n".join(document["rules"])
    # Mihomo has no first-class "direct"/"block" outbound object; DIRECT and
    # REJECT are built-in policy keywords used directly in rules.
    assert "DIRECT" in rule_text
    assert "REJECT" in rule_text
    assert "proxy" in proxy_names
    assert "node-example" in group_names


# ---------------------------------------------------------------------------
# node-example is clearly documented as a placeholder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "xray-lite.json",
        "xray-server.json",
        "sing-box-lite.json",
        "sing-box-server.json",
    ],
)
def test_node_example_outbound_is_documented_as_placeholder(name):
    document = _load_json_template(name)
    node_example = next(
        outbound
        for outbound in document["outbounds"]
        if outbound["tag"] == "node-example"
    )
    comment = node_example.get("_comment", "")
    assert "PLACEHOLDER" in comment
    assert "replace" in comment.lower()


@pytest.mark.parametrize("name", ["mihomo-lite.yaml", "mihomo-server.yaml"])
def test_mihomo_node_example_group_is_documented_as_placeholder(name):
    raw_text = (TEMPLATES_DIR / name).read_text(encoding="utf-8")
    assert "PLACEHOLDER" in raw_text
    assert "node-example" in raw_text


# ---------------------------------------------------------------------------
# Lite: private -> DIRECT, spy -> BLOCK only, blocked -> PROXY, ru -> DIRECT,
# default -> PROXY
# ---------------------------------------------------------------------------


def test_xray_lite_rule_order_and_default():
    document = _load_json_template("xray-lite.json")
    rules = document["routing"]["rules"]

    # Rule 1: private/local -> direct via native geoip:private.
    assert rules[0]["ip"] == ["geoip:private"]
    assert rules[0]["outboundTag"] == "direct"

    # Every subsequent domain/ip target referencing "spy" must point to block,
    # and must appear before any "blocked" or "ru" rule.
    kind_by_index = []
    for rule in rules[1:]:
        targets = rule.get("domain", []) + rule.get("ip", [])
        joined = " ".join(targets)
        if "spy" in joined:
            assert rule["outboundTag"] == "block"
            kind_by_index.append("spy")
        elif "blocked" in joined:
            assert rule["outboundTag"] == "proxy"
            kind_by_index.append("blocked")
        elif "ru" in joined:
            assert rule["outboundTag"] == "direct"
            kind_by_index.append("ru")

    # spy comes before blocked, which comes before ru.
    assert kind_by_index.index("spy") < kind_by_index.index("blocked")
    assert kind_by_index.index("blocked") < kind_by_index.index("ru")

    # Only spy is blocked by default in lite -- no ads/trackers/malware/phishing.
    all_text = json.dumps(document)
    for excluded in ("ads", "trackers", "malware", "phishing"):
        assert f":{excluded}\"" not in all_text

    # Default (unmatched) outbound is proxy: the first declared outbound.
    assert document["outbounds"][0]["tag"] == "proxy"


def test_singbox_lite_rule_order_and_default():
    document = _load_json_template("sing-box-lite.json")
    rules = document["route"]["rules"]

    assert rules[0]["ip_is_private"] is True
    assert rules[0]["outbound"] == "direct"

    rule_set_order = [
        rule["rule_set"][0]
        for rule in rules[1:]
        if "rule_set" in rule
    ]
    assert rule_set_order.index("spy") < rule_set_order.index("blocked")
    assert rule_set_order.index("blocked") < rule_set_order.index("ru")

    spy_rule = next(rule for rule in rules if rule.get("rule_set") == ["spy"])
    assert spy_rule["outbound"] == "block"
    blocked_rule = next(rule for rule in rules if rule.get("rule_set") == ["blocked"])
    assert blocked_rule["outbound"] == "proxy"

    assert document["route"]["final"] == "proxy"

    tags = {rs["tag"] for rs in document["route"]["rule_set"]}
    for excluded in ("ads", "trackers", "malware", "phishing"):
        assert excluded not in tags


def test_mihomo_lite_rule_order_and_default():
    document = _load_yaml_template("mihomo-lite.yaml")
    rules = document["rules"]

    assert rules[0] == "PRIVATE,DIRECT"

    def index_of(prefix):
        return next(i for i, rule in enumerate(rules) if rule.startswith(prefix))

    spy_index = index_of("RULE-SET,spy,")
    blocked_index = index_of("RULE-SET,blocked,")
    ru_index = index_of("RULE-SET,ru,")

    assert spy_index < blocked_index < ru_index
    assert rules[spy_index].endswith(",REJECT")
    assert rules[blocked_index].endswith(",proxy")
    assert rules[ru_index].endswith(",DIRECT")

    # Final catch-all is MATCH,proxy (default unmatched -> proxy for lite).
    assert rules[-1] == "MATCH,proxy"

    provider_names = set(document.get("rule-providers", {}))
    for excluded in ("ads", "trackers", "malware", "phishing"):
        assert excluded not in provider_names


# ---------------------------------------------------------------------------
# Server: private -> DIRECT, bittorrent -> BLOCK, malware/phishing/spy/ads ->
# BLOCK, example services -> node-example, default -> DIRECT
# ---------------------------------------------------------------------------


def test_xray_server_rule_order_and_default():
    document = _load_json_template("xray-server.json")
    rules = document["routing"]["rules"]

    assert rules[0]["ip"] == ["geoip:private"]
    assert rules[0]["outboundTag"] == "direct"

    assert rules[1]["protocol"] == ["bittorrent"]
    assert rules[1]["outboundTag"] == "block"

    deny_categories = {"malware", "phishing", "spy", "ads"}
    deny_rule = next(
        rule
        for rule in rules
        if any(
            any(cat in target for cat in deny_categories)
            for target in rule.get("domain", []) + rule.get("ip", [])
        )
    )
    assert deny_rule["outboundTag"] == "block"
    for category in deny_categories:
        joined = " ".join(deny_rule.get("domain", []) + deny_rule.get("ip", []))
        assert category in joined or any(
            category in " ".join(r.get("domain", []) + r.get("ip", []))
            and r["outboundTag"] == "block"
            for r in rules
        )

    service_rule = next(
        rule for rule in rules if rule.get("outboundTag") == "node-example"
    )
    assert "google" in " ".join(service_rule["domain"])

    # Default (unmatched) outbound is direct: the first declared outbound.
    assert document["outbounds"][0]["tag"] == "direct"


def test_xray_server_uses_protocol_field_for_bittorrent():
    document = _load_json_template("xray-server.json")
    rules = document["routing"]["rules"]
    bittorrent_rules = [rule for rule in rules if rule.get("protocol")]
    assert len(bittorrent_rules) == 1
    assert bittorrent_rules[0]["protocol"] == ["bittorrent"]
    assert bittorrent_rules[0]["outboundTag"] == "block"


def test_singbox_server_rule_order_default_and_documents_bittorrent_nonparity():
    document = _load_json_template("sing-box-server.json")
    rules = document["route"]["rules"]

    assert rules[0]["ip_is_private"] is True
    assert rules[0]["outbound"] == "direct"

    bt_rule = next(rule for rule in rules if rule.get("protocol") == ["bittorrent"])
    assert bt_rule["outbound"] == "block"

    deny_rule = next(
        rule
        for rule in rules
        if rule.get("rule_set") == ["malware", "phishing", "spy", "ads"]
    )
    assert deny_rule["outbound"] == "block"

    service_rule = next(
        rule for rule in rules if rule.get("outbound") == "node-example"
    )
    assert "google" in service_rule["rule_set"]

    assert document["route"]["final"] == "direct"

    # Documented non-parity: sing-box cannot express Xray-equivalent
    # BitTorrent protocol detection.
    full_text = json.dumps(document)
    assert "NON-PARITY" in full_text
    assert "bittorrent" in full_text.lower()


def test_mihomo_server_rule_order_default_and_documents_bittorrent_nonparity():
    document = _load_yaml_template("mihomo-server.yaml")
    rules = document["rules"]

    assert rules[0] == "PRIVATE,DIRECT"

    def index_of(prefix):
        return next(i for i, rule in enumerate(rules) if rule.startswith(prefix))

    malware_index = index_of("RULE-SET,malware,")
    phishing_index = index_of("RULE-SET,phishing,")
    spy_index = index_of("RULE-SET,spy,")
    ads_index = index_of("RULE-SET,ads,")
    for rule_index in (malware_index, phishing_index, spy_index, ads_index):
        assert rules[rule_index].endswith(",REJECT")

    google_index = index_of("RULE-SET,google,")
    assert rules[google_index].endswith(",node-example")

    assert rules[-1] == "MATCH,DIRECT"

    raw_text = (TEMPLATES_DIR / "mihomo-server.yaml").read_text(encoding="utf-8")
    assert "NON-PARITY" in raw_text
    assert "BitTorrent" in raw_text


# ---------------------------------------------------------------------------
# render_examples: copying + placeholder substitution into dist/examples
# ---------------------------------------------------------------------------


def test_render_examples_writes_output_contract_layout_with_substitutions(tmp_path):
    dist = tmp_path / "dist"
    written = render_examples(
        TEMPLATES_DIR,
        dist,
        version="2026.08.26.0000-deadbeef",
        cdn_base="https://routing.akent.site/latest",
    )

    expected_relative_paths = {
        "xray/lite.json",
        "xray/server.json",
        "sing-box/lite.json",
        "sing-box/server.json",
        "mihomo/lite.yaml",
        "mihomo/server.yaml",
    }
    assert set(written) == expected_relative_paths

    for relative_path in expected_relative_paths:
        output_path = dist / "examples" / relative_path
        assert output_path.is_file()
        content = output_path.read_text(encoding="utf-8")
        assert "{{VERSION}}" not in content
        assert "{{CDN_BASE}}" not in content
        assert "2026.08.26.0000-deadbeef" in content
        assert "https://routing.akent.site/latest" in content


def test_render_examples_output_files_remain_parseable_after_substitution(tmp_path):
    dist = tmp_path / "dist"
    render_examples(
        TEMPLATES_DIR, dist, version="2026.08.26.0000-deadbeef"
    )

    json_relatives = (
        "xray/lite.json",
        "xray/server.json",
        "sing-box/lite.json",
        "sing-box/server.json",
    )
    for relative in json_relatives:
        path = dist / "examples" / relative
        json.loads(path.read_text(encoding="utf-8"))
    for relative in ("mihomo/lite.yaml", "mihomo/server.yaml"):
        path = dist / "examples" / relative
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(document, dict)


def test_render_examples_is_atomic_and_replaces_stale_files(tmp_path):
    dist = tmp_path / "dist"
    stale_dir = dist / "examples" / "xray"
    stale_dir.mkdir(parents=True)
    (stale_dir / "stale.json").write_text("{}", encoding="utf-8")

    render_examples(TEMPLATES_DIR, dist, version="2026.08.26.0000-deadbeef")

    assert not (dist / "examples" / "xray" / "stale.json").exists()
    assert (dist / "examples" / "xray" / "lite.json").is_file()


# ---------------------------------------------------------------------------
# Templates never reference a CIDR/geoip artifact for a domain-only category.
#
# render_geoip_config (src/ru_routing/render.py) and the Mihomo *-ipcidr.mrs
# output (src/ru_routing/generate.py) only ever emit a canonical category into
# a geoip/ipcidr artifact when at least one of its upstream sources actually
# produces CIDR entries (source input_type "geoip_dat", or the jutsu-dev
# "blocked-cidrs" plain_text feed). A canonical category whose every upstream
# source is domain-only (e.g. geosite_dat) will never appear in geoip.dat /
# *-ipcidr.mrs, so a template referencing it as an IP-match/rule-provider
# source is a dangling reference: it will fail Xray's native config test and
# 404 at runtime for Mihomo's rule-provider fetch.
# ---------------------------------------------------------------------------


class _FixtureGeodataReader:
    """A minimal reader honoring the real geoip_dat/geosite_dat contract:
    geoip_dat artifacts yield CIDR entries, geosite_dat artifacts yield
    domain entries. This mirrors what the real native decoders in
    src/ru_routing/parsers.py dispatch on (source.input_type), not a
    naming guess."""

    def read(self, input_type: str, category: str, artifact: Path):
        # Values are unique per (input_type, category) so unrelated
        # canonical categories never collide during resolve_datasets'
        # cross-category precedence resolution. Derived from a stable
        # SHA-256 digest rather than Python's built-in ``hash()`` --
        # ``hash()`` on str/tuple is salted per-process by
        # PYTHONHASHSEED (random by default), which can make unrelated
        # (input_type, category) pairs collide on the same synthetic
        # index under some seeds, causing spurious ResolutionErrors
        # unrelated to the code under test.
        digest = hashlib.sha256(f"{input_type}:{category}".encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % 250 + 1
        if input_type == "geoip_dat":
            return (GeodataRule(kind=RuleKind.CIDR, value=f"203.0.{index}.0/24"),)
        return (
            GeodataRule(kind=RuleKind.DOMAIN_SUFFIX, value=f"fixture{index}.test"),
        )


def _cidr_capable_canonical_categories() -> frozenset[str]:
    """Derive, from the real source/category config and the real
    fetch-normalize-resolve pipeline, which canonical categories end up
    with at least one CIDR entry -- i.e. the same determination
    render_geoip_config and mihomo_mrs_behaviors make on real resolved
    data (via models.category_is_cidr_capable), run here against a
    synthetic fixture build instead of live network fetches."""

    registry = load_registry(CONFIG_DIR / "sources.yaml")
    policy = load_policy(CONFIG_DIR / "categories.yaml")

    fetched: list[FetchedSource] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for source in registry.sources:
            object_paths: dict[str, tuple[Path, ...]] = {}
            for category in source.expected_categories:
                if source.input_type == "plain_text":
                    path = root / f"{source.name.replace('/', '_')}-{category}.lst"
                    # Content shape (not the category name) is what the real
                    # parser (_parse_line) uses to decide domain vs CIDR, so
                    # fixture content is written to match what each real,
                    # documented feed actually contains (see the *.lst
                    # filenames in config/sources.yaml: "*-ipsets.lst" feeds
                    # are CIDR lists, everything else is a domain list).
                    locations = source.category_locations.get(category, ())
                    is_ipset_feed = any(
                        "ipset" in location for location in locations
                    )
                    # Unique per (source, category) for the same collision-
                    # avoidance reason as _FixtureGeodataReader above, and
                    # derived from a stable SHA-256 digest rather than
                    # Python's salted ``hash()`` for the same reason.
                    digest = hashlib.sha256(
                        f"{source.name}:{category}".encode("utf-8")
                    ).digest()
                    index = int.from_bytes(digest[:4], "big") % 250 + 1
                    content = (
                        f"203.0.{index}.0/24\n"
                        if is_ipset_feed
                        else f"fixture{index}.test\n"
                    )
                    path.write_text(content, encoding="utf-8")
                    object_paths[category] = (path,)
                else:
                    artifact = root / f"{source.name.replace('/', '_')}.dat"
                    artifact.write_bytes(b"\x00")
                    object_paths[category] = (artifact,)
            fetched.append(
                FetchedSource(
                    name=source.name,
                    resolved_revision="fixture",
                    sha256="0" * 64,
                    license=source.license,
                    object_paths=object_paths,
                    observed_freshness_lag_hours=None,
                )
            )

        entries = normalize_sources(
            fetched,
            registry=registry,
            geodata_reader=_FixtureGeodataReader(),
        )

    build = resolve_datasets(entries, policy)

    cidr_capable: set[str] = set()
    for dataset in (build.lite, build.server):
        for name, category in dataset.categories.items():
            if category_is_cidr_capable(category):
                cidr_capable.add(name)
    return frozenset(cidr_capable)


def _xray_geoip_categories(document: dict) -> set[str]:
    """Extract every canonical category referenced via ext:geoip*.dat: in an
    Xray template's routing rules (i.e. every IP-match geoip reference)."""

    categories: set[str] = set()
    pattern = re.compile(r"^ext:geoip[^:]*\.dat:(.+)$")
    for rule in document["routing"]["rules"]:
        for target in rule.get("ip", []):
            match = pattern.match(target)
            if match:
                categories.add(match.group(1))
    return categories


def _mihomo_ipcidr_categories(document: dict) -> set[str]:
    """Extract every canonical category with an ipcidr-behavior rule-provider
    in a Mihomo template."""

    categories: set[str] = set()
    for name, provider in document.get("rule-providers", {}).items():
        if provider.get("behavior") == "ipcidr":
            category = name[: -len("-ipcidr")] if name.endswith("-ipcidr") else name
            categories.add(category)
    return categories


@pytest.mark.parametrize("name", ["xray-lite.json", "xray-server.json"])
def test_xray_templates_only_reference_geoip_for_cidr_capable_categories(name):
    cidr_capable = _cidr_capable_canonical_categories()
    document = _load_json_template(name)
    referenced = _xray_geoip_categories(document)

    dangling = referenced - cidr_capable
    assert not dangling, (
        f"{name} references ext:geoip*.dat for categories with no CIDR "
        f"source in config/categories.yaml: {sorted(dangling)}"
    )


@pytest.mark.parametrize("name", ["mihomo-lite.yaml", "mihomo-server.yaml"])
def test_mihomo_templates_only_declare_ipcidr_providers_for_cidr_capable_categories(
    name,
):
    cidr_capable = _cidr_capable_canonical_categories()
    document = _load_yaml_template(name)
    referenced = _mihomo_ipcidr_categories(document)

    dangling = referenced - cidr_capable
    assert not dangling, (
        f"{name} declares an ipcidr rule-provider for categories with no "
        f"CIDR source in config/categories.yaml: {sorted(dangling)}"
    )


def test_domain_only_categories_fixture_sanity():
    """Guard the test itself: confirm the known domain-only categories this
    bug class affects are not accidentally classified as CIDR-capable, and
    known CIDR-capable categories are not accidentally excluded."""

    cidr_capable = _cidr_capable_canonical_categories()
    for domain_only in ("spy", "malware", "phishing", "ads"):
        assert domain_only not in cidr_capable
    for cidr_category in ("ru", "blocked", "ru-geoip", "geoip-global"):
        assert cidr_category in cidr_capable


def test_render_examples_is_deterministic(tmp_path):
    dist = tmp_path / "dist"
    render_examples(TEMPLATES_DIR, dist, version="2026.08.26.0000-deadbeef")
    first = {
        str(path.relative_to(dist)): path.read_text(encoding="utf-8")
        for path in sorted((dist / "examples").rglob("*"))
        if path.is_file()
    }

    render_examples(TEMPLATES_DIR, dist, version="2026.08.26.0000-deadbeef")
    second = {
        str(path.relative_to(dist)): path.read_text(encoding="utf-8")
        for path in sorted((dist / "examples").rglob("*"))
        if path.is_file()
    }

    assert first == second
