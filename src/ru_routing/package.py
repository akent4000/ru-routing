"""Package a validated build into an auditable, checksummed release tree.

This stage consumes the ``dist`` tree already produced by Tasks 6-8
(``generate``/``validate``); it does not regenerate artifacts. It:

- computes the two independent fingerprints described by the design doc's
  "Change Detection and Versioning" section (``content_fingerprint`` and
  ``policy_fingerprint``);
- decides whether a release is warranted by comparing those fingerprints
  and category/size anomaly thresholds against the previous manifest
  (``plan_release``);
- writes ``SHA256SUMS`` (covering every public artifact except itself and
  ``manifest.json``) and then ``manifest.json`` last, embedding the SHA-256
  of the just-written ``SHA256SUMS`` file and the ``content_fingerprint``
  (``package_build``).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .config import ThresholdPolicy
from .fetch import FetchedSource
from .resolve import ConflictReport, ResolvedBuild

SCHEMA_VERSION = "1"


class AnomalyError(RuntimeError):
    """Raised when a category count or total size crosses its configured bound."""


class PackagingError(RuntimeError):
    """Raised when a build tree cannot be packaged into a release."""


@dataclass(frozen=True)
class PolicyConfigs:
    """The exact policy inputs that determine how entries are produced.

    ``policy_fingerprint`` covers the source-registry version, the
    category-mapping table version, and the schema version -- not the
    entries those configs produce. Neither ``SourceRegistry`` nor
    ``CategoryPolicy`` currently declares an explicit version field, so the
    "version" of each is concretely defined here as the raw, canonical
    bytes of its version-controlled config file (``config/sources.yaml``
    and ``config/categories.yaml``): any reviewed change to either file
    changes its hash, which is exactly what "version" means for a
    version-controlled policy document. ``schema_version`` is this
    package's own manifest schema version (``SCHEMA_VERSION`` above).
    """

    source_registry_bytes: bytes
    category_mapping_bytes: bytes
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True)
class BuildMetadata:
    """Everything ``package_build``/``plan_release`` need beyond the dist tree."""

    build: ResolvedBuild
    policy_configs: PolicyConfigs
    sources: tuple[FetchedSource, ...]
    conflicts: ConflictReport
    thresholds: ThresholdPolicy
    previous_manifest: Mapping[str, object] | None
    built_at: str
    tool_versions: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ReleaseDecision:
    """Whether to release, the computed version, and why."""

    should_release: bool
    version: str | None
    reason: str
    content_fingerprint: str
    policy_fingerprint: str


@dataclass(frozen=True)
class Manifest:
    """The fully populated ``manifest.json`` content."""

    schema_version: str
    release_version: str | None
    content_fingerprint: str
    policy_fingerprint: str
    sources: tuple[Mapping[str, object], ...]
    category_counts: Mapping[str, int]
    total_size_bytes: int
    artifact_sizes: Mapping[str, int]
    checksums: Mapping[str, str]
    sha256sums_sha256: str
    tool_versions: Mapping[str, str]
    conflict_statistics: Mapping[str, int]
    built_at: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", tuple(self.sources))
        object.__setattr__(
            self, "category_counts", MappingProxyType(dict(self.category_counts))
        )
        object.__setattr__(
            self, "artifact_sizes", MappingProxyType(dict(self.artifact_sizes))
        )
        object.__setattr__(self, "checksums", MappingProxyType(dict(self.checksums)))
        object.__setattr__(
            self, "tool_versions", MappingProxyType(dict(self.tool_versions))
        )
        object.__setattr__(
            self,
            "conflict_statistics",
            MappingProxyType(dict(self.conflict_statistics)),
        )

    def to_json_dict(self) -> dict[str, object]:
        """Return the deterministic JSON-serializable manifest document."""

        return {
            "schema_version": self.schema_version,
            "release_version": self.release_version,
            "content_fingerprint": self.content_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "sources": list(self.sources),
            "category_counts": dict(sorted(self.category_counts.items())),
            "total_size_bytes": self.total_size_bytes,
            "artifact_sizes": dict(sorted(self.artifact_sizes.items())),
            "checksums": dict(sorted(self.checksums.items())),
            "sha256sums_sha256": self.sha256sums_sha256,
            "tool_versions": dict(sorted(self.tool_versions.items())),
            "conflict_statistics": dict(sorted(self.conflict_statistics.items())),
            "built_at": self.built_at,
        }


def content_fingerprint(build: ResolvedBuild) -> str:
    """Hash only the canonical lite/server dataset content.

    Excludes every operational/timestamp field: it is derived purely from
    ``Dataset.to_canonical_json()``, which already normalizes ordering and
    carries no build-time metadata.
    """

    digest = hashlib.sha256()
    digest.update(build.lite.to_canonical_json())
    digest.update(b"\x00")
    digest.update(build.server.to_canonical_json())
    return digest.hexdigest()


def policy_fingerprint(configs: PolicyConfigs) -> str:
    """Hash the source-registry version, category-mapping version, and schema version.

    See ``PolicyConfigs`` for how "version" is concretely defined.
    """

    digest = hashlib.sha256()
    digest.update(configs.source_registry_bytes)
    digest.update(b"\x00")
    digest.update(configs.category_mapping_bytes)
    digest.update(b"\x00")
    digest.update(configs.schema_version.encode("utf-8"))
    return digest.hexdigest()


def plan_release(current: ResolvedBuild, metadata: BuildMetadata) -> ReleaseDecision:
    """Decide whether to release, compute the version, and check anomalies."""

    current_content = content_fingerprint(current)
    current_policy = policy_fingerprint(metadata.policy_configs)

    previous = metadata.previous_manifest
    if previous is None:
        _check_anomalies(current, metadata, previous=None)
        return ReleaseDecision(
            should_release=True,
            version=_version_string(current_content, metadata.built_at),
            reason="initial release",
            content_fingerprint=current_content,
            policy_fingerprint=current_policy,
        )

    previous_content = previous.get("content_fingerprint")
    previous_policy = previous.get("policy_fingerprint")
    changed = current_content != previous_content or current_policy != previous_policy

    _check_anomalies(current, metadata, previous=previous)

    if not changed:
        return ReleaseDecision(
            should_release=False,
            version=None,
            reason="no change",
            content_fingerprint=current_content,
            policy_fingerprint=current_policy,
        )

    content_changed = current_content != previous_content
    reason = "content changed" if content_changed else "policy changed"
    return ReleaseDecision(
        should_release=True,
        version=_version_string(current_content, metadata.built_at),
        reason=reason,
        content_fingerprint=current_content,
        policy_fingerprint=current_policy,
    )


def _version_string(content_digest: str, built_at: str) -> str:
    timestamp = datetime.fromisoformat(built_at).astimezone(timezone.utc)
    return f"{timestamp:%Y.%m.%d.%H%M}-{content_digest[:8]}"


def _check_anomalies(
    build: ResolvedBuild,
    metadata: BuildMetadata,
    *,
    previous: Mapping[str, object] | None,
) -> None:
    if previous is None:
        return
    previous_counts = previous.get("category_counts")
    if not isinstance(previous_counts, dict):
        return
    ratio = metadata.thresholds.category_count_change_ratio
    current_counts = _category_counts(build)
    for key, previous_count in previous_counts.items():
        current_count = current_counts.get(key, 0)
        if not isinstance(previous_count, (int, float)) or previous_count <= 0:
            continue
        change = abs(current_count - previous_count) / previous_count
        if change > ratio:
            raise AnomalyError(
                f"category {key} changed by {change:.2%}, "
                f"exceeding the configured {ratio:.2%} threshold "
                f"({previous_count} -> {current_count})"
            )
    previous_size = previous.get("total_size_bytes")
    if isinstance(previous_size, (int, float)) and previous_size > 0:
        current_size = _content_size_bytes(build)
        size_ratio = metadata.thresholds.size_change_ratio
        size_change = abs(current_size - previous_size) / previous_size
        if size_change > size_ratio:
            raise AnomalyError(
                f"total content size changed by {size_change:.2%}, "
                f"exceeding the configured {size_ratio:.2%} threshold "
                f"({previous_size} -> {current_size})"
            )


def _category_counts(build: ResolvedBuild) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dataset_name, dataset in (("lite", build.lite), ("server", build.server)):
        for category_name, category in dataset.categories.items():
            counts[f"{dataset_name}:{category_name}"] = len(category.entries)
    return counts


def _content_size_bytes(build: ResolvedBuild) -> int:
    return len(build.lite.to_canonical_json()) + len(build.server.to_canonical_json())


def package_build(dist: Path, metadata: BuildMetadata) -> Manifest:
    """Write SHA256SUMS then manifest.json from the already-generated dist tree.

    Ordering is load-bearing: artifacts already exist in ``dist``;
    ``SHA256SUMS`` is written first (covering every public file except
    itself and ``manifest.json``), and ``manifest.json`` is written last so
    it can embed the SHA-256 of the just-written ``SHA256SUMS`` file.
    """

    destination = Path(dist)
    if not destination.is_dir():
        raise PackagingError(f"dist directory is absent: {destination}")

    public_files = sorted(
        path
        for path in destination.rglob("*")
        if path.is_file() and path.name not in {"SHA256SUMS", "manifest.json"}
    )
    checksums: dict[str, str] = {}
    artifact_sizes: dict[str, int] = {}
    lines: list[str] = []
    for path in public_files:
        relative = str(path.relative_to(destination))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        checksums[relative] = digest
        artifact_sizes[relative] = path.stat().st_size
        lines.append(f"{digest}  {relative}\n")

    checksums_path = destination / "SHA256SUMS"
    checksums_path.write_text("".join(lines), encoding="utf-8")
    sha256sums_digest = hashlib.sha256(checksums_path.read_bytes()).hexdigest()

    decision = plan_release(metadata.build, metadata)

    manifest = Manifest(
        schema_version=metadata.policy_configs.schema_version,
        release_version=decision.version,
        content_fingerprint=decision.content_fingerprint,
        policy_fingerprint=decision.policy_fingerprint,
        sources=tuple(_source_document(source) for source in metadata.sources),
        category_counts=_category_counts(metadata.build),
        total_size_bytes=_content_size_bytes(metadata.build),
        artifact_sizes=artifact_sizes,
        checksums=checksums,
        sha256sums_sha256=sha256sums_digest,
        tool_versions=dict(metadata.tool_versions),
        conflict_statistics=_conflict_statistics(metadata.conflicts),
        built_at=metadata.built_at,
    )

    manifest_path = destination / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            manifest.to_json_dict(),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def _source_document(source: FetchedSource) -> Mapping[str, object]:
    return {
        "name": source.name,
        "resolved_revision": source.resolved_revision,
        "sha256": source.sha256,
        "license": {
            "spdx": source.license.spdx,
            "redistribution_reviewed": source.license.redistribution_reviewed,
        },
        "observed_freshness_lag_hours": source.observed_freshness_lag_hours,
    }


def _conflict_statistics(conflicts: ConflictReport) -> Mapping[str, int]:
    return {
        "overlaps_before": len(conflicts.overlaps_before),
        "overlaps_after": len(conflicts.overlaps_after),
        "resolved": len(conflicts.resolved),
    }
