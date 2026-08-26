from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ru_routing.config import LicenseMetadata, ThresholdPolicy
from ru_routing.fetch import FetchedSource
from ru_routing.models import Category, Dataset, RuleEntry, RuleKind
from ru_routing.package import (
    AnomalyError,
    BuildMetadata,
    PolicyConfigs,
    content_fingerprint,
    package_build,
    plan_release,
    policy_fingerprint,
)
from ru_routing.resolve import ConflictReport, ResolvedBuild

FIXTURES = Path(__file__).parent / "fixtures"


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


def _policy_configs(
    *, sources: bytes = b"sources-v1", categories: bytes = b"categories-v1"
) -> PolicyConfigs:
    return PolicyConfigs(
        source_registry_bytes=sources,
        category_mapping_bytes=categories,
        schema_version="1",
    )


def _fetched_source(name: str = "hydraponique/roscomvpn-geoip") -> FetchedSource:
    return FetchedSource(
        name=name,
        resolved_revision="a" * 40,
        sha256="b" * 64,
        license=LicenseMetadata(spdx="GPL-3.0-only", redistribution_reviewed=True),
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


# --- plan_release ---


def _previous_manifest() -> dict:
    return json.loads((FIXTURES / "previous-manifest.json").read_text())


def test_plan_release_triggers_when_content_changed():
    metadata = _metadata(
        build=_build(extra=True), previous_manifest=_previous_manifest()
    )
    decision = plan_release(metadata.build, metadata)
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
    decision = plan_release(metadata.build, metadata)
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
    decision = plan_release(metadata.build, metadata)
    assert decision.should_release is False
    assert decision.reason == "no change"


def test_plan_release_computes_version_string_format():
    previous = _previous_manifest()
    metadata = _metadata(build=_build(extra=True), previous_manifest=previous)
    decision = plan_release(metadata.build, metadata)
    fingerprint8 = content_fingerprint(metadata.build)[:8]
    assert decision.version.startswith("2026.08.26.1234-")
    assert decision.version == f"2026.08.26.1234-{fingerprint8}"


def test_plan_release_fails_on_category_count_anomaly():
    previous = _previous_manifest()
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
        plan_release(metadata.build, metadata)


def test_plan_release_first_build_has_no_previous_manifest_and_releases():
    metadata = _metadata(build=_build(), previous_manifest=None)
    decision = plan_release(metadata.build, metadata)
    assert decision.should_release is True
    assert decision.reason == "initial release"


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


def test_package_build_records_source_provenance_license_and_freshness(tmp_path):
    dist = tmp_path / "dist"
    _write_dist(dist)
    metadata = _metadata()
    manifest = package_build(dist, metadata)
    source_entry = manifest.sources[0]
    assert source_entry["name"] == "hydraponique/roscomvpn-geoip"
    assert source_entry["resolved_revision"] == "a" * 40
    assert source_entry["license"]["spdx"] == "GPL-3.0-only"


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
