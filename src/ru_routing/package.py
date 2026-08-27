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
  (``package_build``);
- archives the now-complete ``dist`` tree (including ``SHA256SUMS`` and
  ``manifest.json`` themselves) into a single deterministic
  ``<version>.tar.gz`` sibling of ``dist``, so Task 11 (publication) has one
  file to upload alongside the primary individual assets.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .config import SourceRemovalMigration, ThresholdPolicy
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
    #: Must be a timezone-aware ISO 8601 timestamp (UTC recommended); a
    #: naive timestamp causes ``_version_string`` to raise ``PackagingError``.
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
    archive_filename: str | None = None
    archive_sha256: str | None = None
    archive_size_bytes: int | None = None

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
            "archive_filename": self.archive_filename,
            "archive_sha256": self.archive_sha256,
            "archive_size_bytes": self.archive_size_bytes,
        }

    @classmethod
    def from_json_dict(cls, data: Mapping[str, object]) -> "Manifest":
        """Reconstruct a ``Manifest`` from a ``to_json_dict``-shaped document.

        The inverse of ``to_json_dict``. Used by the CLI (Task 11 wiring) to
        reload a previously written ``manifest.json`` -- either the manifest
        of the build being published (from ``--dist``) or a historical
        manifest describing R2's currently-live state (``--previous-manifest``
        / a target rollback version's manifest) -- as a real ``Manifest``
        instead of a raw ``dict``, since ``PublishPlan``/``rollback`` need the
        typed object, not the JSON document. Field-for-field symmetric with
        ``to_json_dict``'s keys; raises ``KeyError`` if a required field is
        missing, which is intentional -- a manifest.json missing a required
        field is malformed and should fail loudly rather than silently
        default.
        """

        return cls(
            schema_version=data["schema_version"],
            release_version=data["release_version"],
            content_fingerprint=data["content_fingerprint"],
            policy_fingerprint=data["policy_fingerprint"],
            sources=tuple(data["sources"]),
            category_counts=dict(data["category_counts"]),
            total_size_bytes=data["total_size_bytes"],
            artifact_sizes=dict(data["artifact_sizes"]),
            checksums=dict(data["checksums"]),
            sha256sums_sha256=data["sha256sums_sha256"],
            tool_versions=dict(data["tool_versions"]),
            conflict_statistics=dict(data["conflict_statistics"]),
            built_at=data["built_at"],
            archive_filename=data.get("archive_filename"),
            archive_sha256=data.get("archive_sha256"),
            archive_size_bytes=data.get("archive_size_bytes"),
        )


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


def plan_release(metadata: BuildMetadata) -> ReleaseDecision:
    """Decide whether to release, compute the version, and check anomalies."""

    current_content = content_fingerprint(metadata.build)
    current_policy = policy_fingerprint(metadata.policy_configs)

    previous = metadata.previous_manifest
    if previous is None:
        _check_anomalies(metadata, previous=None)
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

    source_removal = _approved_source_removal(
        previous=previous,
        current_sources=metadata.sources,
        migrations=metadata.thresholds.source_removal_migrations,
        previous_policy=previous_policy,
        current_policy=current_policy,
    )
    _check_anomalies(
        metadata,
        previous=previous,
        reset_category_keys=(
            source_removal.reset_category_keys if source_removal else frozenset()
        ),
        reset_size=source_removal.reset_size if source_removal else False,
    )

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
    parsed = datetime.fromisoformat(built_at)
    if parsed.tzinfo is None:
        raise PackagingError(
            f"built_at is a naive timestamp (no timezone info): {built_at!r}; "
            "expected a timezone-aware ISO 8601 timestamp (UTC recommended)"
        )
    timestamp = parsed.astimezone(timezone.utc)
    return f"{timestamp:%Y.%m.%d.%H%M}-{content_digest[:8]}"


def _is_sha256_digest(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _previous_source_names(previous: Mapping[str, object]) -> frozenset[str] | None:
    raw_sources = previous.get("sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        return None
    names: list[str] = []
    for raw_source in raw_sources:
        if not isinstance(raw_source, dict):
            return None
        name = raw_source.get("name")
        if not isinstance(name, str) or not name:
            return None
        names.append(name)
    if len(set(names)) != len(names):
        return None
    return frozenset(names)


def _current_source_names(
    current_sources: tuple[FetchedSource, ...],
) -> frozenset[str] | None:
    names = [source.name for source in current_sources]
    if (
        not names
        or any(not isinstance(name, str) or not name for name in names)
        or len(set(names)) != len(names)
    ):
        return None
    return frozenset(names)


def _approved_source_removal(
    *,
    previous: Mapping[str, object],
    current_sources: tuple[FetchedSource, ...],
    migrations: tuple[SourceRemovalMigration, ...],
    previous_policy: object,
    current_policy: str,
) -> SourceRemovalMigration | None:
    if not _is_sha256_digest(previous_policy) or previous_policy == current_policy:
        return None
    previous_names = _previous_source_names(previous)
    current_names = _current_source_names(current_sources)
    if previous_names is None or current_names is None:
        return None
    if not current_names < previous_names:
        return None
    removed_names = previous_names - current_names
    matches = [
        migration
        for migration in migrations
        if migration.removed_source_ids == removed_names
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _check_anomalies(
    metadata: BuildMetadata,
    *,
    previous: Mapping[str, object] | None,
    reset_category_keys: frozenset[str] = frozenset(),
    reset_size: bool = False,
) -> None:
    if previous is None:
        return
    previous_counts = previous.get("category_counts")
    if not isinstance(previous_counts, dict):
        return
    ratio = metadata.thresholds.category_count_change_ratio
    current_counts = _category_counts(metadata.build)
    for key, previous_count in previous_counts.items():
        if key in reset_category_keys:
            continue
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
    if not reset_size and isinstance(previous_size, (int, float)) and previous_size > 0:
        current_size = _content_size_bytes(metadata.build)
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
    """Write SHA256SUMS, manifest.json, then a deterministic archive of ``dist``.

    Ordering is load-bearing: artifacts already exist in ``dist``;
    ``SHA256SUMS`` is written first (covering every public file except
    itself and ``manifest.json``), and ``manifest.json`` is written next so
    it can embed the SHA-256 of the just-written ``SHA256SUMS`` file.

    The archive is created last, from the now-complete tree (it deliberately
    includes ``SHA256SUMS`` and ``manifest.json`` -- a consumer who only
    downloads the archive still needs both). This creates an unavoidable
    ordering constraint: the archive's own checksum cannot be embedded in
    the copy of ``manifest.json`` that ships *inside* the archive (a file
    cannot describe the checksum of the container it is already sealed
    inside). Instead, ``manifest.json`` is written twice: once with
    ``archive_*`` fields left ``None`` (this is the copy the archive
    contains), and once more, after the archive exists, with those fields
    populated (this is the copy that ships alongside the archive in
    ``dist`` and is what Task 11's publication step reads to learn the
    archive's name/hash for upload). Only the second, on-disk copy carries
    the archive metadata; this is intentional, not a bug.
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

    decision = plan_release(metadata)

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
    _write_manifest_json(manifest_path, manifest)

    version = decision.version or "unreleased"
    archive_filename = f"{version}.tar.gz"
    archive_path = destination.parent / archive_filename
    _create_archive(destination, archive_path)
    archive_bytes = archive_path.read_bytes()
    manifest = Manifest(
        **{
            **_manifest_kwargs(manifest),
            "archive_filename": archive_filename,
            "archive_sha256": hashlib.sha256(archive_bytes).hexdigest(),
            "archive_size_bytes": len(archive_bytes),
        }
    )
    _write_manifest_json(manifest_path, manifest)
    return manifest


def _manifest_kwargs(manifest: Manifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "release_version": manifest.release_version,
        "content_fingerprint": manifest.content_fingerprint,
        "policy_fingerprint": manifest.policy_fingerprint,
        "sources": manifest.sources,
        "category_counts": manifest.category_counts,
        "total_size_bytes": manifest.total_size_bytes,
        "artifact_sizes": manifest.artifact_sizes,
        "checksums": manifest.checksums,
        "sha256sums_sha256": manifest.sha256sums_sha256,
        "tool_versions": manifest.tool_versions,
        "conflict_statistics": manifest.conflict_statistics,
        "built_at": manifest.built_at,
    }


def _write_manifest_json(manifest_path: Path, manifest: Manifest) -> None:
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


_ARCHIVE_FIXED_MTIME = 0
_ARCHIVE_ROOT_DIR = "release"


def _create_archive(destination: Path, archive_path: Path) -> None:
    """Tar+gzip the complete ``dist`` tree into a byte-deterministic archive.

    Determinism requires normalizing everything ``tarfile`` would otherwise
    pull from the filesystem or the environment:

    - member order is the sorted relative path (filesystem iteration order
      is not guaranteed);
    - ``mtime``, ``uid``, ``gid``, ``uname``, ``gname`` are forced to fixed
      constants rather than the actual filesystem/OS values;
    - ``mode`` is forced to a fixed constant (0o644) rather than whatever
      the umask/filesystem produced;
    - the gzip container's own embedded mtime and OS byte are zeroed via
      ``mtime=0`` and a raw ``GzipFile`` (``tarfile.open(..., mode="w:gz")``
      would otherwise stamp the wall-clock time into the gzip header,
      which alone would make two identical archives differ byte-for-byte
      even with every tar member normalized).

    All entries are written under a fixed root directory name
    (``release/``) rather than the temporary ``dist`` path, so extraction
    is predictable regardless of the build's tmp/output directory name.
    """

    relative_paths = sorted(
        path.relative_to(destination)
        for path in destination.rglob("*")
        if path.is_file()
    )

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    with open(archive_path, "wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=_ARCHIVE_FIXED_MTIME
        ) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for relative in relative_paths:
                    absolute = destination / relative
                    info = tar.gettarinfo(
                        absolute, arcname=f"{_ARCHIVE_ROOT_DIR}/{relative.as_posix()}"
                    )
                    info.mtime = _ARCHIVE_FIXED_MTIME
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mode = 0o644
                    info.pax_headers = {}
                    with open(absolute, "rb") as fileobj:
                        tar.addfile(info, fileobj)


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
