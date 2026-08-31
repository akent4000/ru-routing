from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from ru_routing.cli import main
from ru_routing.config import ConfigError, load_policy, load_registry, load_thresholds

EXPECTED_SOURCES = {
    "aireps/geosite",
    "runetfreedom/russia-v2ray-rules-dat",
    "jutsu-dev/ru-route-lists",
    "Loyalsoldier/v2ray-rules-dat",
    "itdoginfo/allow-domains",
    "hydraponique/roscomvpn-geoip",
    "kirilllavrov/RU-domain-list-for-whitelist",
    "builtin/private-networks",
}

UNVERIFIED_LICENSE_SOURCES = ()


@pytest.mark.parametrize("source_name", UNVERIFIED_LICENSE_SOURCES)
def test_unverified_license_source_cannot_enter_validated_registry(source_name):
    registry = load_registry(Path("config/sources.yaml"))

    with pytest.raises(ConfigError, match="unknown source ID"):
        registry.resolve(source_name)


@pytest.mark.parametrize("source_name", UNVERIFIED_LICENSE_SOURCES)
def test_registry_rejects_reintroduced_source_without_license_review(
    source_name, tmp_path
):
    path = tmp_path / "sources.yaml"
    path.write_text(
        Path("config/sources.yaml").read_text(encoding="utf-8")
        + f"""
  - name: {source_name}
    url: https://example.test/candidate
    input_type: plain_text
    layout: per_category_urls
    required: true
    expected_categories: [candidate]
    category_locations:
      candidate: https://example.test/candidate
    attribution: candidate contributors
    license:
      spdx: NOASSERTION
      redistribution_reviewed: false
    freshness:
      max_age_hours: 48
""",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="redistribution_reviewed must be true"):
        load_registry(path)


def test_every_source_is_required_mapped_and_license_reviewed():
    registry = load_registry(Path("config/sources.yaml"))
    policy = load_policy(Path("config/categories.yaml"))

    assert {source.name for source in registry.sources} == EXPECTED_SOURCES
    assert all(source.required for source in registry.sources)
    assert all(source.license.spdx for source in registry.sources)
    assert all(source.license.redistribution_reviewed for source in registry.sources)
    assert set(policy.source_categories) == registry.declared_category_keys()


def test_loaded_policies_are_immutable_and_preserve_freshness_and_tiers():
    registry = load_registry(Path("config/sources.yaml"))
    policy = load_policy(Path("config/categories.yaml"))
    thresholds = load_thresholds(Path("config/thresholds.yaml"))
    aireps = next(
        source for source in registry.sources if source.name == "aireps/geosite"
    )

    assert aireps.freshness.max_sync_lag_hours == 48
    assert aireps.expected_categories == ("category-ru", "private", "whitelist")
    assert (
        policy.source_categories[
            "runetfreedom/russia-v2ray-rules-dat:win-spy"
        ].tier.value
        == "deny"
    )
    assert policy.source_categories[
        "runetfreedom/russia-v2ray-rules-dat:category-ru"
    ].datasets == frozenset({"lite", "server"})
    assert policy.canonical_category("blocked").tier.value == "explicit_blocked"
    assert policy.canonical_category("blocked").datasets == frozenset({"server"})
    assert all(
        set(source.category_locations) == set(source.expected_categories)
        for source in registry.sources
    )
    jutsu = registry.resolve("jutsu-dev/ru-route-lists")
    assert jutsu.layout == "release_assets"
    assert jutsu.freshness.max_age_hours == 48
    assert jutsu.category_locations["blocked-domains"] == (
        "https://github.com/jutsu-dev/ru-route-lists/releases/download/"
        "latest/rkn-domains.lst",
    )
    assert thresholds.category_count_change_ratio == 0.5
    (source_removal,) = thresholds.source_removal_migrations
    # Historical migration record: fixes the exact set of sources removed
    # at that past transition. itdoginfo/allow-domains was later
    # re-included (see config.py's INITIAL_SOURCE_IDS and the design doc's
    # 2026-08-29 reversal note) -- this recorded event describes what
    # happened at the time, independent of the current registry state.
    assert source_removal.removed_source_ids == frozenset(
        {"hydraponique/roscomvpn-geoip", "itdoginfo/allow-domains"}
    )
    assert source_removal.reset_category_keys == frozenset(
        {
            "lite:ru",
            "server:ru",
            "lite:ru-inside",
            "server:ru-inside",
            "server:ru-outside",
            "server:ru-services",
            "lite:ads",
            "server:ads",
            "lite:trackers",
            "server:trackers",
            "lite:spy",
            "server:spy",
            "server:malware",
            "server:phishing",
            "server:google",
            "server:youtube",
            "server:telegram",
            "server:discord",
            "server:meta",
            "server:github",
            "server:streaming",
            "server:ai",
            "server:ru-geoip",
            "server:geoip-global",
        }
    )


    assert source_removal.reset_size is True
    assert source_removal.expected_previous_policy_fingerprint == (
        "3622e0da67ebb699da90527f95f006e973632f67c6a39efb051dab1ea7b79b92"
    )
    assert source_removal.expected_current_policy_fingerprint == (
        "13beb03426ea7153649e2317c36c6247de9c8a91ee255b90149204b4e2862e48"
    )
    category_scope_by_previous_policy = {
        migration.expected_previous_policy_fingerprint: migration
        for migration in thresholds.category_scope_migrations
    }
    category_scope = category_scope_by_previous_policy[
        "c387b5303f85676c0570140b6f089694ecb481ed2ec51301d4c36bfec89783d7"
    ]
    assert category_scope.expected_current_policy_fingerprint == (
        "13beb03426ea7153649e2317c36c6247de9c8a91ee255b90149204b4e2862e48"
    )
    private_scope = category_scope_by_previous_policy[
        "ff986cb880be20bcf1ebab03d31aeac21c24dda9c068ef92f685313a03866d3d"
    ]
    assert private_scope.expected_current_policy_fingerprint == (
        "13beb03426ea7153649e2317c36c6247de9c8a91ee255b90149204b4e2862e48"
    )
    assert private_scope.reset_category_keys == frozenset(
        {"lite:private", "server:private"}
    )
    assert private_scope.reset_size is True

    whitelist_scope = category_scope_by_previous_policy[
        "6a3fc32f22d69529fb1723c73c8c61e5f5e804adb34d27badf23db38b1d7e1db"
    ]
    assert whitelist_scope.expected_current_policy_fingerprint == (
        "13beb03426ea7153649e2317c36c6247de9c8a91ee255b90149204b4e2862e48"
    )
    assert whitelist_scope.reset_category_keys == frozenset(
        {"lite:ru-whitelist", "server:ru-whitelist", "server:ru-direct-geoip"}
    )
    assert whitelist_scope.reset_size is True

    with pytest.raises(FrozenInstanceError):
        aireps.url = "https://invalid.example"  # type: ignore[misc]
    with pytest.raises(TypeError):
        policy.source_categories["other"] = object()  # type: ignore[index]


def test_jutsu_has_normal_freshness_without_temporary_exception():
    registry = load_registry(Path("config/sources.yaml"))

    assert registry.resolve("jutsu-dev/ru-route-lists").freshness.max_age_hours == 48
    assert "720 hours" not in Path("README.md").read_text(encoding="utf-8")


def test_registry_resolves_source_attribution_and_validates_fixture_overrides(tmp_path):
    registry = load_registry(Path("config/sources.yaml"))
    fixture = tmp_path / "aireps-geosite.dat"
    fixture.write_text("fixture", encoding="utf-8")

    source = registry.resolve("aireps/geosite")
    overrides = registry.fixture_overrides({source.name: fixture})

    assert source.license.redistribution_reviewed
    assert registry.attribution_for(source.name) == source.attribution
    assert overrides == {"aireps/geosite": fixture}
    with pytest.raises(ConfigError):
        registry.resolve("unknown/source")
    with pytest.raises(ConfigError):
        registry.fixture_overrides({"unknown/source": fixture})


@pytest.mark.parametrize(
    ("first", "second"),
    [
        ("datasets: [lite], tier: thematic", "datasets: [server], tier: thematic"),
        ("datasets: [lite], tier: thematic", "datasets: [lite], tier: deny"),
    ],
)
def test_policy_rejects_inconsistent_canonical_tier_or_dataset_assignments(
    first, second, tmp_path
):
    path = tmp_path / "categories.yaml"
    path.write_text(
        "mappings:\n"
        "  - {source: first, source_category: one, canonical_category: shared,\n"
        f"    {first}}}\n"
        "  - {source: second, source_category: two, canonical_category: shared,\n"
        f"    {second}}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError):
        load_policy(path)


@pytest.mark.parametrize(
    ("replacement", "value"),
    [
        ("name: aireps/geosite", "name: invalid/source"),
        ("input_type: geoip_dat", "input_type: unsupported"),
        ("layout: single_artifact", "layout: unsupported"),
    ],
)
def test_registry_requires_the_initial_source_ids_and_supported_semantics(
    replacement, value, tmp_path
):
    path = tmp_path / "sources.yaml"
    path.write_text(
        Path("config/sources.yaml")
        .read_text(encoding="utf-8")
        .replace(replacement, value, 1),
        encoding="utf-8",
    )

    with pytest.raises(ConfigError):
        load_registry(path)


def test_loader_wraps_non_string_yaml_keys_as_configuration_errors(tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text("? [non, string]\n: value\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_registry(path)


@pytest.mark.parametrize(
    ("loader", "contents"),
    [
        (
            load_registry,
            "sources:\n  - name: one\n    url: https://example.test\n"
            "    input_type: plain\n    required: true\n    expected_categories: [ru]\n"
            "    license: {spdx: MIT, redistribution_reviewed: true}\n"
            "    unknown: rejected\n",
        ),
        (
            load_registry,
            "sources:\n  - name: one\n    url: https://example.test\n"
            "    input_type: plain\n    required: false\n"
            "    expected_categories: [ru]\n"
            "    license: {spdx: MIT, redistribution_reviewed: true}\n",
        ),
        (
            load_registry,
            "sources:\n  - name: one\n    url: https://example.test\n"
            "    input_type: plain\n    required: true\n    expected_categories: [ru]\n"
            "    license: {spdx: MIT, redistribution_reviewed: false}\n",
        ),
        (
            load_policy,
            "mappings:\n  - source: one\n    source_category: ru\n"
            "    canonical_category: ru\n    datasets: [lite]\n    tier: thematic\n"
            "  - source: one\n    source_category: ru\n"
            "    canonical_category: ru\n    datasets: [lite]\n    tier: thematic\n",
        ),
        (
            load_policy,
            "mappings:\n  - source: one\n    source_category: ru\n"
            "    canonical_category: ru\n    tier: thematic\n",
        ),
        (
            load_policy,
            "mappings:\n  - source: one\n    source_category: ru\n"
            "    canonical_category: ru\n    datasets: [lite]\n",
        ),
        (
            load_thresholds,
            "category_count_change_ratio: 0.5\n"
            "category_count_change_ratio: 0.7\nsize_change_ratio: 0.5\n",
        ),
    ],
)
def test_loaders_reject_invalid_schema(loader, contents, tmp_path):
    path = tmp_path / "invalid.yaml"
    path.write_text(contents, encoding="utf-8")

    with pytest.raises(ConfigError):
        loader(path)


def test_config_only_check_loads_all_policies(capsys):
    assert main(["check", "--config-only"]) == 0
    assert "configuration is valid" in capsys.readouterr().out
