from __future__ import annotations

import hashlib
import json
import tarfile
from dataclasses import replace
from pathlib import Path

import pytest

import ru_routing.package as package_module
from ru_routing.config import LicenseMetadata, ThresholdPolicy, load_thresholds
from ru_routing.fetch import DegradedSource, FetchedSource
from ru_routing.models import Category, Dataset, RuleEntry, RuleKind
from ru_routing.package import (
    AnomalyError,
    BuildMetadata,
    Manifest,
    PackagingError,
    PolicyConfigs,
    content_fingerprint,
    package_build,
    plan_release,
    policy_fingerprint,
)
from ru_routing.render import Representation, RepresentationReport
from ru_routing.resolve import ConflictReport, ResolvedBuild

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]
LICENSE_PATHS = {
    "LICENSES.md",
    "licenses/upstream/aireps-geosite/LICENSE",
    "licenses/upstream/jutsu-dev-ru-route-lists/LICENSE",
    "licenses/upstream/loyalsoldier-v2ray-rules-dat/LICENSE",
    "licenses/upstream/runetfreedom-russia-v2ray-rules-dat/LICENSE",
    "licenses/upstream/v2fly-domain-list-community/LICENSE",
}


def _entry(kind: RuleKind, value: str) -> RuleEntry:
    return RuleEntry(kind, value, frozenset({"fixture"}))


def _build(*, extra: bool = False) -> ResolvedBuild:
    entries = {
        _entry(RuleKind.DOMAIN, "blocked.example"),
        _entry(RuleKind.DOMAIN, "blocked2.example"),
        _entry(RuleKind.DOMAIN, "blocked3.example"),
    }
    if extra:
        entries.add(_entry(RuleKind.DOMAIN, "extra.example"))
    blocked = Category("blocked", frozenset(entries))
    ru_ip = Category("ru-ip", frozenset({_entry(RuleKind.CIDR, "203.0.113.0/24")}))
    dataset = Dataset({"blocked": blocked, "ru-ip": ru_ip})
    return ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))


def _build_without_ru_ip() -> ResolvedBuild:
    previous_shape = _build()
    dataset = Dataset({"blocked": previous_shape.lite.categories["blocked"]})
    return ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))


def _build_with_upstream_private_domains() -> ResolvedBuild:
    builtin_cidrs = (
        FIXTURES
        / "upstreams/registry/builtin_private-networks--private.lst"
    ).read_text(encoding="utf-8").splitlines()
    entries = {
        RuleEntry(
            RuleKind.CIDR,
            cidr,
            frozenset({"builtin/private-networks"}),
        )
        for cidr in builtin_cidrs
    }
    entries.update(
        RuleEntry(
            RuleKind.DOMAIN,
            f"private-{index}.example",
            frozenset({"aireps/geosite"}),
        )
        for index in range(22)
    )
    private = Category(
        "private",
        frozenset(entries),
    )
    dataset = Dataset({"private": private})
    return ResolvedBuild(dataset, dataset, ConflictReport((), (), ()))


def _policy_configs(
    *, sources: bytes = b"sources-v1", categories: bytes = b"categories-v1"
) -> PolicyConfigs:
    return PolicyConfigs(
        source_registry_bytes=sources,
        category_mapping_bytes=categories,
        schema_version="1",
    )


def _fetched_source(name: str = "fixture/geoip") -> FetchedSource:
    return FetchedSource(
        name=name,
        resolved_revision="a" * 40,
        sha256="b" * 64,
        license=LicenseMetadata(spdx="MIT", redistribution_reviewed=True),
        object_paths={},
        observed_freshness_lag_hours=None,
    )


def _write_dist(dist: Path) -> None:
    (dist / "xray").mkdir(parents=True)
    (dist / "xray" / "geoip.dat").write_bytes(b"geoip-bytes")
    (dist / "raw" / "lite" / "domains").mkdir(parents=True)
    (dist / "raw" / "lite" / "domains" / "blocked.txt").write_text(
        "blocked.example\n", encoding="utf-8"
    )


_DEFAULT_THRESHOLDS = ThresholdPolicy(
    category_count_change_ratio=0.5, size_change_ratio=0.5
)

DEGRADED_JUTSU = DegradedSource(
    name="jutsu-dev/ru-route-lists",
    status="degraded",
    reason="stale",
    excluded_from_build=True,
    observed_freshness_age_hours=49.0,
    max_age_hours=48,
)

_CURRENT_SOURCE_IDS = (
    "aireps/geosite",
    "runetfreedom/russia-v2ray-rules-dat",
    "jutsu-dev/ru-route-lists",
    "Loyalsoldier/v2ray-rules-dat",
)
_REMOVED_SOURCE_IDS = frozenset(
    {
        "hydraponique/roscomvpn-geoip",
        "itdoginfo/allow-domains",
    }
)
_MIGRATION_AFFECTED_CATEGORY_KEYS = frozenset(
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
_CURRENT_POLICY_CONFIGS = PolicyConfigs(
    source_registry_bytes=Path("config/sources.yaml").read_bytes(),
    category_mapping_bytes=Path("config/categories.yaml").read_bytes(),
)
_MIGRATION_THRESHOLDS = load_thresholds(Path("config/thresholds.yaml"))


def _metadata(
    *,
    build: ResolvedBuild | None = None,
    previous_manifest: dict | None = None,
) -> BuildMetadata:
    resolved_build = build or _build()
    return BuildMetadata(
        build=resolved_build,
        policy_configs=_policy_configs(),
        sources=(_fetched_source(),),
        conflicts=resolved_build.conflicts,
        thresholds=_DEFAULT_THRESHOLDS,
        previous_manifest=previous_manifest,
        built_at="2026-08-26T12:34:00+00:00",
        tool_versions={"xray": "1.0.0"},
    )


# --- content_fingerprint ---


def test_content_fingerprint_ignores_timestamps():
    build_a = _build()
    build_b = _build()
    assert content_fingerprint(build_a) == content_fingerprint(build_b)


def test_content_fingerprint_changes_with_content():
    assert content_fingerprint(_build()) != content_fingerprint(_build(extra=True))


def test_content_fingerprint_is_hex_sha256():
    digest = content_fingerprint(_build())
    assert len(digest) == 64
    int(digest, 16)


# --- policy_fingerprint ---


def test_policy_fingerprint_changes_when_source_registry_changes():
    base = policy_fingerprint(_policy_configs())
    changed = policy_fingerprint(_policy_configs(sources=b"sources-v2"))
    assert base != changed


def test_policy_fingerprint_changes_when_category_mapping_changes():
    base = policy_fingerprint(_policy_configs())
    changed = policy_fingerprint(_policy_configs(categories=b"categories-v2"))
    assert base != changed


def test_policy_fingerprint_changes_when_schema_version_changes():
    base = policy_fingerprint(_policy_configs())
    changed = policy_fingerprint(
        PolicyConfigs(
            source_registry_bytes=b"sources-v1",
            category_mapping_bytes=b"categories-v1",
            schema_version="2",
        )
    )
    assert base != changed


def test_policy_fingerprint_is_stable_for_identical_input():
    left = policy_fingerprint(_policy_configs())
    right = policy_fingerprint(_policy_configs())
    assert left == right


def test_approved_migrations_target_current_policy_fingerprint():
    current = policy_fingerprint(_CURRENT_POLICY_CONFIGS)

    assert all(
        migration.expected_current_policy_fingerprint == current
        for migration in (
            *_MIGRATION_THRESHOLDS.source_removal_migrations,
            *_MIGRATION_THRESHOLDS.category_scope_migrations,
        )
    )


# --- plan_release ---


def _previous_manifest() -> dict:
    return json.loads((FIXTURES / "previous-manifest.json").read_text())


def _source_manifest_entries(source_ids) -> list[dict[str, str]]:
    return [{"name": source_id} for source_id in source_ids]


def _source_removal_metadata(
    *,
    previous: dict,
    current_source_ids=_CURRENT_SOURCE_IDS,
) -> BuildMetadata:
    build = _build_without_ru_ip()
    return BuildMetadata(
        build=build,
        policy_configs=_CURRENT_POLICY_CONFIGS,
        sources=tuple(_fetched_source(source_id) for source_id in current_source_ids),
        conflicts=build.conflicts,
        thresholds=_MIGRATION_THRESHOLDS,
        previous_manifest=previous,
        built_at="2026-08-26T12:34:00+00:00",
        tool_versions={"xray": "1.0.0"},
    )


def _pre_removal_manifest() -> dict:
    previous = _previous_manifest()
    (source_removal,) = _MIGRATION_THRESHOLDS.source_removal_migrations
    previous["policy_fingerprint"] = (
        source_removal.expected_previous_policy_fingerprint
    )
    previous["sources"] = _source_manifest_entries(
        (*_CURRENT_SOURCE_IDS, *_REMOVED_SOURCE_IDS)
    )
    previous["category_counts"] = {
        category_key: 100 for category_key in _MIGRATION_AFFECTED_CATEGORY_KEYS
    }
    previous["total_size_bytes"] = 100_000
    return previous


def test_plan_release_triggers_when_content_changed():
    metadata = _metadata(
        build=_build(extra=True), previous_manifest=_previous_manifest()
    )
    decision = plan_release(metadata)
    assert decision.should_release is True


def test_plan_release_triggers_on_policy_only_change_with_unchanged_content():
    previous = _previous_manifest()
    # previous manifest content fingerprint matches current build's content fingerprint
    build = _build()
    metadata = BuildMetadata(
        build=build,
        policy_configs=_policy_configs(sources=b"sources-v2"),
        sources=(_fetched_source(),),
        conflicts=build.conflicts,
        thresholds=_DEFAULT_THRESHOLDS,
        previous_manifest=previous,
        built_at="2026-08-26T12:34:00+00:00",
        tool_versions={"xray": "1.0.0"},
    )
    decision = plan_release(metadata)
    assert decision.should_release is True


def test_plan_release_reports_no_change_when_both_fingerprints_match():
    previous = _previous_manifest()
    build = _build()
    metadata = BuildMetadata(
        build=build,
        policy_configs=_policy_configs(),
        sources=(_fetched_source(),),
        conflicts=build.conflicts,
        thresholds=_DEFAULT_THRESHOLDS,
        previous_manifest=previous,
        built_at="2026-08-26T12:34:00+00:00",
        tool_versions={"xray": "1.0.0"},
    )
    # Make the previous manifest's fingerprints equal to the current build's.
    previous["content_fingerprint"] = content_fingerprint(metadata.build)
    previous["policy_fingerprint"] = policy_fingerprint(metadata.policy_configs)
    decision = plan_release(metadata)
    assert decision.should_release is False
    assert decision.reason == "no change"


def test_plan_release_computes_version_string_format():
    previous = _previous_manifest()
    metadata = _metadata(build=_build(extra=True), previous_manifest=previous)
    decision = plan_release(metadata)
    fingerprint8 = content_fingerprint(metadata.build)[:8]
    assert decision.version.startswith("2026.08.26.1234-")
    assert decision.version == f"2026.08.26.1234-{fingerprint8}"


def test_plan_release_fails_on_category_count_anomaly():
    previous = _previous_manifest()
    previous["policy_fingerprint"] = policy_fingerprint(_policy_configs())
    # previous manifest declares far fewer 'blocked' entries than the current
    # build now has, exceeding the configured change ratio.
    previous["category_counts"] = {
        "lite:blocked": 1,
        "lite:ru-ip": 1,
        "server:blocked": 1,
        "server:ru-ip": 1,
    }
    metadata = _metadata(build=_build(extra=True), previous_manifest=previous)
    with pytest.raises(AnomalyError):
        plan_release(metadata)


def test_quarantine_allows_only_its_affected_category_count_change():
    build = _build()
    previous = {
        "content_fingerprint": "a" * 64,
        "policy_fingerprint": "b" * 64,
        "category_counts": {"server:blocked": 100},
        "total_size_bytes": package_module._content_size_bytes(build),
    }
    metadata = _metadata(build=build, previous_manifest=previous)
    metadata = replace(
        metadata,
        quarantined_category_keys=frozenset({"server:blocked"}),
    )

    assert plan_release(metadata).should_release is True

    with pytest.raises(AnomalyError, match="category server:blocked"):
        plan_release(replace(metadata, quarantined_category_keys=frozenset()))


def test_plan_release_allows_exact_approved_source_removal_baseline_reset():
    metadata = _source_removal_metadata(previous=_pre_removal_manifest())

    decision = plan_release(metadata)

    assert decision.should_release is True


def test_plan_release_allows_exact_upstream_private_policy_migration():
    previous = {
        "content_fingerprint": (
            "0ae7a179efe8a8ab9b6f4db88dc717fc2b8f12dfab8a5401d97f4feab6f1b766"
        ),
        "policy_fingerprint": (
            "ff986cb880be20bcf1ebab03d31aeac21c24dda9c068ef92f685313a03866d3d"
        ),
        "category_counts": {"lite:private": 21, "server:private": 21},
        "total_size_bytes": 289_029_891,
    }
    build = _build_with_upstream_private_domains()
    metadata = BuildMetadata(
        build=build,
        policy_configs=_CURRENT_POLICY_CONFIGS,
        sources=(_fetched_source("aireps/geosite"),),
        conflicts=build.conflicts,
        thresholds=_MIGRATION_THRESHOLDS,
        previous_manifest=previous,
        built_at="2026-08-31T12:34:00+00:00",
        tool_versions={"xray": "1.0.0"},
    )

    decision = plan_release(metadata)

    assert decision.should_release is True
    assert decision.policy_fingerprint == (
        "13beb03426ea7153649e2317c36c6247de9c8a91ee255b90149204b4e2862e48"
    )


def test_plan_release_still_blocks_unrelated_anomaly_during_source_removal():
    previous = _pre_removal_manifest()
    previous["category_counts"]["lite:blocked"] = 1
    metadata = _source_removal_metadata(previous=previous)

    with pytest.raises(AnomalyError, match="category lite:blocked"):
        plan_release(metadata)


def test_plan_release_source_replacement_cannot_use_removal_baseline_reset():
    previous = _pre_removal_manifest()
    metadata = _source_removal_metadata(
        previous=previous,
        current_source_ids=(*_CURRENT_SOURCE_IDS, "replacement/example"),
    )

    with pytest.raises(AnomalyError):
        plan_release(metadata)


def test_plan_release_unapproved_source_removal_cannot_reset_baseline():
    previous = _pre_removal_manifest()
    previous["sources"] = _source_manifest_entries(
        (*_CURRENT_SOURCE_IDS, "unapproved/example")
    )
    metadata = _source_removal_metadata(previous=previous)

    with pytest.raises(AnomalyError):
        plan_release(metadata)


def test_plan_release_wrong_valid_previous_policy_cannot_reset_baseline():
    previous = _pre_removal_manifest()
    previous["policy_fingerprint"] = "f" * 64
    metadata = _source_removal_metadata(previous=previous)

    with pytest.raises(AnomalyError):
        plan_release(metadata)


def test_plan_release_wrong_valid_current_policy_cannot_reset_baseline():
    previous = _pre_removal_manifest()
    metadata = _source_removal_metadata(previous=previous)
    metadata = replace(
        metadata,
        policy_configs=_policy_configs(sources=b"unapproved-current-policy"),
    )

    with pytest.raises(AnomalyError):
        plan_release(metadata)


@pytest.mark.parametrize(
    "prior_metadata_change",
    [
        lambda previous: previous.pop("sources"),
        lambda previous: previous.update(sources=[]),
        lambda previous: previous.update(sources=[{"name": "malformed"}, None]),
        lambda previous: previous["sources"].append(previous["sources"][0]),
        lambda previous: previous.pop("policy_fingerprint"),
        lambda previous: previous.update(policy_fingerprint="not-a-digest"),
    ],
    ids=(
        "missing-sources",
        "empty-sources",
        "malformed-source-entry",
        "duplicate-source-name",
        "missing-policy-fingerprint",
        "malformed-policy-fingerprint",
    ),
)
def test_plan_release_malformed_or_missing_prior_metadata_cannot_reset_baseline(
    prior_metadata_change,
):
    previous = _pre_removal_manifest()
    prior_metadata_change(previous)
    metadata = _source_removal_metadata(previous=previous)

    with pytest.raises(AnomalyError):
        plan_release(metadata)


def test_plan_release_first_build_has_no_previous_manifest_and_releases():
    metadata = _metadata(build=_build(), previous_manifest=None)
    decision = plan_release(metadata)
    assert decision.should_release is True
    assert decision.reason == "initial release"


def test_plan_release_raises_on_naive_built_at():
    resolved_build = _build()
    metadata = BuildMetadata(
        build=resolved_build,
        policy_configs=_policy_configs(),
        sources=(_fetched_source(),),
        conflicts=resolved_build.conflicts,
        thresholds=_DEFAULT_THRESHOLDS,
        previous_manifest=None,
        built_at="2026-08-26T12:34:00",  # naive: no tzinfo
        tool_versions={"xray": "1.0.0"},
    )
    with pytest.raises(PackagingError):
        plan_release(metadata)


# --- package_build ---


def test_package_build_writes_sha256sums_before_manifest(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    metadata = _metadata()
    package_build(dist, metadata)
    checksums = dist / "SHA256SUMS"
    manifest_path = dist / "manifest.json"
    assert checksums.exists()
    assert manifest_path.exists()
    assert checksums.stat().st_mtime <= manifest_path.stat().st_mtime


def test_package_build_sha256sums_excludes_itself_and_manifest(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    metadata = _metadata()
    package_build(dist, metadata)
    lines = (dist / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    listed_paths = {line.split(maxsplit=1)[1] for line in lines}
    assert "SHA256SUMS" not in listed_paths
    assert "manifest.json" not in listed_paths


def test_package_build_manifest_embeds_sha256sums_hash(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    metadata = _metadata()
    package_build(dist, metadata)
    manifest = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
    checksums_bytes = (dist / "SHA256SUMS").read_bytes()
    expected = hashlib.sha256(checksums_bytes).hexdigest()
    assert manifest["sha256sums_sha256"] == expected


def test_package_build_manifest_contains_required_fields(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    metadata = _metadata()
    manifest = package_build(dist, metadata)
    assert manifest.schema_version
    assert manifest.content_fingerprint == content_fingerprint(metadata.build)
    assert manifest.sources
    assert manifest.category_counts
    assert manifest.artifact_sizes
    assert manifest.checksums
    assert manifest.tool_versions == {"xray": "1.0.0"}


def test_manifest_records_stale_source_without_listing_it_as_used(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)

    manifest = package_build(
        dist, replace(_metadata(), degraded_sources=(DEGRADED_JUTSU,))
    )

    expected_degraded_sources = [
        {
            "excluded_from_build": True,
            "max_age_hours": 48,
            "observed_freshness_age_hours": 49.0,
            "reason": "stale",
            "source": "jutsu-dev/ru-route-lists",
            "status": "degraded",
        }
    ]
    assert manifest.to_json_dict()["degraded_sources"] == expected_degraded_sources
    assert "jutsu-dev/ru-route-lists" not in {
        source["name"] for source in manifest.sources
    }
    with tarfile.open(dist.parent / manifest.archive_filename, "r:gz") as archive:
        member = next(
            item for item in archive.getmembers() if item.name.endswith("manifest.json")
        )
        bundled_manifest = json.loads(archive.extractfile(member).read())
    assert bundled_manifest["degraded_sources"] == expected_degraded_sources


def test_manifest_parses_older_document_without_degraded_sources(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    document = package_build(dist, _metadata()).to_json_dict()
    document.pop("degraded_sources")

    assert Manifest.from_json_dict(document).degraded_sources == ()


def test_package_build_preserves_representation_losses_after_archive_rewrite(
    tmp_path, monkeypatch
):
    dist = tmp_path / "dist"
    _write_dist(dist)
    loss = Representation(
        target="future-engine",
        dataset="server",
        category="thematic",
        kind=RuleKind.DOMAIN_REGEX,
        value="^unrepresentable\\.example$",
        represented=False,
        reason="rule kind is unsupported",
    )
    monkeypatch.setattr(
        package_module,
        "representation_report",
        lambda _build: RepresentationReport((loss,)),
    )

    package_build(dist, _metadata())

    manifest = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["representation_losses"] == [
        {
            "target": "future-engine",
            "dataset": "server",
            "category": "thematic",
            "kind": "domain_regex",
            "value": "^unrepresentable\\.example$",
        }
    ]


def test_package_build_records_source_provenance_license_and_freshness(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    metadata = _metadata()
    manifest = package_build(dist, metadata)
    source_entry = manifest.sources[0]
    assert source_entry["name"] == "fixture/geoip"
    assert source_entry["resolved_revision"] == "a" * 40
    assert source_entry["license"]["spdx"] == "MIT"


def test_package_build_checksums_are_valid_for_every_public_file(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    metadata = _metadata()
    package_build(dist, metadata)
    lines = (dist / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    for line in lines:
        digest, relative = line.split(maxsplit=1)
        actual = hashlib.sha256((dist / relative).read_bytes()).hexdigest()
        assert actual == digest


def test_package_build_writes_index_page_with_current_artifact_links(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    artifacts = {
        "sing-box/lite/blocked.srs": b"sing-box-lite",
        "sing-box/server/blocked.srs": b"sing-box-server",
        "mihomo/lite/blocked-domain.mrs": b"mihomo-lite",
        "mihomo/server/blocked-domain.mrs": b"mihomo-server",
    }
    for relative, content in artifacts.items():
        path = dist / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    manifest = package_build(dist, _metadata())

    page = (dist / "index.html").read_text(encoding="utf-8")
    assert "RU routing datasets" in page
    assert 'href="https://routing.akent.site/manifest.json"' in page
    assert 'href="https://routing.akent.site/SHA256SUMS"' in page
    assert 'href="https://routing.akent.site/latest/xray/geoip.dat"' in page
    assert (
        'href="https://routing.akent.site/latest/sing-box/server/blocked.srs"'
        in page
    )
    assert (
        'href="https://routing.akent.site/latest/mihomo/server/blocked-domain.mrs"'
        in page
    )
    assert "latest_version" in page
    assert "<script" not in page.lower()
    assert "index.html" in manifest.checksums
    assert manifest.artifact_sizes["index.html"] == len(page.encode("utf-8"))


def test_package_build_two_runs_are_byte_identical_except_built_at(tmp_path):
    dist_a = tmp_path / "dist-a"
    dist_b = tmp_path / "dist-b"
    _write_dist(dist_a)
    _write_dist(dist_b)
    package_build(dist_a, _metadata())
    package_build(dist_b, _metadata())

    manifest_a = json.loads((dist_a / "manifest.json").read_text())
    manifest_b = json.loads((dist_b / "manifest.json").read_text())
    assert manifest_a == manifest_b  # built_at is identical in this fixture too

    checksums_a = (dist_a / "SHA256SUMS").read_bytes()
    checksums_b = (dist_b / "SHA256SUMS").read_bytes()
    assert checksums_a == checksums_b


def test_package_build_raises_when_dist_is_absent(tmp_path):
    dist = tmp_path / "does-not-exist"
    metadata = _metadata()
    with pytest.raises(PackagingError, match="dist directory is absent"):
        package_build(dist, metadata)


# --- archive creation ---


def test_package_build_creates_archive_next_to_dist(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    manifest = package_build(dist, _metadata())
    archive_path = dist.parent / manifest.archive_filename
    assert archive_path.exists()
    assert archive_path.name.endswith(".tar.gz")


def test_package_build_archive_contains_manifest_and_sha256sums(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    manifest = package_build(dist, _metadata())
    archive_path = dist.parent / manifest.archive_filename
    with tarfile.open(archive_path, "r:gz") as tar:
        names = set(tar.getnames())
    assert any(name.endswith("manifest.json") for name in names)
    assert any(name.endswith("SHA256SUMS") for name in names)
    assert any(name.endswith("xray/geoip.dat") for name in names)
    assert any(name.endswith("raw/lite/domains/blocked.txt") for name in names)


def test_package_build_includes_inventory_and_upstream_license_texts_everywhere(
    tmp_path,
):
    dist = tmp_path / "dist"
    _write_dist(dist)

    manifest = package_build(dist, _metadata())

    assert (dist / "LICENSES.md").read_bytes() == (
        REPO_ROOT / "LICENSES.md"
    ).read_bytes()
    assert LICENSE_PATHS <= set(manifest.checksums)
    sums_paths = {
        line.split("  ", 1)[1]
        for line in (dist / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    }
    assert LICENSE_PATHS <= sums_paths
    for relative in LICENSE_PATHS:
        assert (dist / relative).is_file()
        assert (dist / relative).stat().st_size > 0

    archive_path = dist.parent / manifest.archive_filename
    with tarfile.open(archive_path, "r:gz") as archive:
        archive_paths = {
            name.removeprefix("release/") for name in archive.getnames()
        }
    assert LICENSE_PATHS <= archive_paths


def test_package_build_archive_checksum_and_size_recorded_in_manifest(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    manifest = package_build(dist, _metadata())
    archive_path = dist.parent / manifest.archive_filename
    archive_bytes = archive_path.read_bytes()
    assert manifest.archive_sha256 == hashlib.sha256(archive_bytes).hexdigest()
    assert manifest.archive_size_bytes == len(archive_bytes)

    on_disk_manifest = json.loads((dist / "manifest.json").read_text())
    assert on_disk_manifest["archive_filename"] == manifest.archive_filename
    assert on_disk_manifest["archive_sha256"] == manifest.archive_sha256
    assert on_disk_manifest["archive_size_bytes"] == manifest.archive_size_bytes


def test_package_build_archive_omits_its_own_checksum_from_its_bundled_manifest(
    tmp_path,
):
    # The manifest.json shipped *inside* the archive cannot know the
    # checksum of the archive that contains it, so those fields are None
    # in that copy -- only the on-disk manifest.json (written after the
    # archive exists) carries the populated archive_* fields.
    dist = tmp_path / "dist"
    _write_dist(dist)
    manifest = package_build(dist, _metadata())
    archive_path = dist.parent / manifest.archive_filename
    with tarfile.open(archive_path, "r:gz") as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith("manifest.json"))
        bundled_manifest = json.loads(tar.extractfile(member).read())
    assert bundled_manifest["archive_sha256"] is None
    assert bundled_manifest["archive_filename"] is None
    assert bundled_manifest["archive_size_bytes"] is None


def test_package_build_two_runs_produce_byte_identical_archives(tmp_path):
    dist_a = tmp_path / "dist-a"
    dist_b = tmp_path / "dist-b"
    _write_dist(dist_a)
    _write_dist(dist_b)
    manifest_a = package_build(dist_a, _metadata())
    manifest_b = package_build(dist_b, _metadata())

    assert manifest_a.archive_filename == manifest_b.archive_filename
    archive_a = (dist_a.parent / manifest_a.archive_filename).read_bytes()
    archive_b = (dist_b.parent / manifest_b.archive_filename).read_bytes()
    assert archive_a == archive_b
    assert manifest_a.archive_sha256 == manifest_b.archive_sha256
