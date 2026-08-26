"""Structural, schema, and rendering tests for the engine configuration examples.

These tests deliberately do not invoke real xray/sing-box/mihomo binaries --
that native `check` validation is pinned Docker tooling introduced in Task 10.
Here we assert the committed templates' JSON/YAML are well-formed and encode
the documented lite/server policy ordering, required outbound tags, and
non-parity notes, plus that ru_routing.render.render_examples correctly
copies and substitutes them into the dist/examples output contract layout.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ru_routing.render import render_examples

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "examples" / "templates"

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
