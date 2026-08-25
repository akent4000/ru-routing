from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from ru_routing.cli import main
from ru_routing.config import ConfigError, load_policy, load_registry, load_thresholds

EXPECTED_SOURCES = {
    "hydraponique/roscomvpn-geoip",
    "aireps/geosite",
    "runetfreedom/russia-v2ray-rules-dat",
    "jutsu-dev/ru-route-lists",
    "itdoginfo/allow-domains",
    "Loyalsoldier/v2ray-rules-dat",
}


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
    assert (
        policy.source_categories["aireps/geosite:category-malware"].tier.value == "deny"
    )
    assert policy.source_categories[
        "hydraponique/roscomvpn-geoip:ru"
    ].datasets == frozenset({"lite", "server"})
    assert policy.canonical_category("blocked").tier.value == "explicit_blocked"
    assert policy.canonical_category("blocked").datasets == frozenset(
        {"lite", "server"}
    )
    assert all(
        set(source.category_locations) == set(source.expected_categories)
        for source in registry.sources
    )
    jutsu = registry.resolve("jutsu-dev/ru-route-lists")
    itdog = registry.resolve("itdoginfo/allow-domains")
    assert jutsu.layout == "release_assets"
    assert jutsu.category_locations["blocked-domains"] == (
        "https://github.com/jutsu-dev/ru-route-lists/releases/download/"
        "latest/rkn-domains.lst",
    )
    assert itdog.layout == "per_category_urls"
    assert all(
        "/c0376e54d78a606c09d6eafad6dd792964edaead/" in location
        for locations in itdog.category_locations.values()
        for location in locations
    )
    assert thresholds.category_count_change_ratio == 0.5

    with pytest.raises(FrozenInstanceError):
        aireps.url = "https://invalid.example"  # type: ignore[misc]
    with pytest.raises(TypeError):
        policy.source_categories["other"] = object()  # type: ignore[index]


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
        ("name: hydraponique/roscomvpn-geoip", "name: invalid/source"),
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
