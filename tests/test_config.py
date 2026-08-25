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
    assert thresholds.category_count_change_ratio == 0.5

    with pytest.raises(FrozenInstanceError):
        aireps.url = "https://invalid.example"  # type: ignore[misc]
    with pytest.raises(TypeError):
        policy.source_categories["other"] = object()  # type: ignore[index]


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
