"""Publish a packaged release to Yandex S3 and GitHub, and support rollback.

Implements the design doc's "Publication and CDN" and "Release Integrity
and Rollback" sections. A completed :func:`ru_routing.package.package_build`
call produces a :class:`~ru_routing.package.Manifest` plus a ``dist`` tree
and a sibling release archive; this module takes that output (wrapped in a
:class:`PublishPlan`) and performs the load-bearing publication sequence:

1. upload and read-back-verify the complete immutable ``/releases/<version>/``
   tree (never overwritten once published);
2. upload the individual objects under ``/latest/*`` -- copies of the
   just-verified immutable tree's content;
3. write the root ``SHA256SUMS`` and then, as the final step, write
   ``/manifest.json`` with the new ``latest_version`` -- the single atomic
   pointer flip. ``manifest.json`` is written strictly last (see
   ``_write_manifest``) so that a single-object S3 PUT's per-object
   atomicity (an S3-compatible PUT either fully lands or fully fails; it
   never leaves partial/ambiguous content visible to a reader) is what
   makes this pointer flip safe: nothing else in the publication sequence
   can fail after ``manifest.json``'s PUT is attempted, so an exception
   from that PUT itself can only mean the pointer never moved;
A draft GitHub Release is created and its assets uploaded *before* Yandex S3
publication begins; it is finalized (made public/non-draft) only after step
3 has been verified.

Failure handling: any failure at or before step 3 (i.e. before the manifest
pointer write is confirmed) triggers cleanup -- delete the draft GitHub
Release, delete the newly uploaded ``/releases/<version>/`` S3 tree, and (if
any ``/latest/*`` objects were already overwritten) restore and verify the
complete ``/latest/*`` tree from the prior immutable version named by the
unchanged root manifest. Cleanup failures are reported explicitly via
``PublishError`` and never change the manifest pointer or create a public
GitHub Release.

Rollback (:func:`rollback`) reuses the verified copy primitive that
``publish_release``'s cleanup path uses to restore ``/latest/*`` from a prior
version. It then installs that target version's checksums and complete
manifest, with the manifest write last. It never rebuilds a release.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Mapping, Protocol, Sequence, runtime_checkable

from .package import Manifest
from .tooling import ToolRunner

_IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
_REVALIDATE_CACHE_CONTROL = "public, max-age=300, must-revalidate"
_S3_MAX_WORKERS = 8


class PublishError(RuntimeError):
    """Raised when publication or rollback cannot complete successfully.

    Never includes credential material -- only object keys, release ids,
    and stage names, which are safe to log.
    """


@dataclass(frozen=True)
class PublishPlan:
    """Everything ``publish_release`` needs beyond the backend.

    ``manifest`` is the fully populated manifest produced by
    ``package_build`` (its ``release_version`` names the version being
    published). ``dist`` is the directory containing every public artifact
    named by ``manifest.checksums``, plus ``SHA256SUMS`` and
    ``manifest.json``. ``archive_path`` is the sibling release archive
    (``<version>.tar.gz``) uploaded as the primary GitHub Release asset.
    ``previous_manifest`` is the manifest currently live in the S3 root
    ``manifest.json`` before this publication begins -- it names the prior
    version cleanup restores ``/latest/*`` from if this publication fails
    partway through; ``None`` for an initial release (nothing to restore).
    """

    manifest: Manifest
    dist: Path
    archive_path: Path
    previous_manifest: Manifest | None = None


@dataclass(frozen=True)
class _ObjectSpec:
    key: str
    content: bytes
    content_type: str
    cache_control: str


@runtime_checkable
class PublishBackend(Protocol):
    """Minimal boundary over S3-compatible and GitHub Release operations.

    Modeled after ``ToolExecutor``/``GeodataReader``/``RegexValidator``'s
    narrow Protocol boundaries elsewhere in this codebase: a small set of
    primitives that both ``FakeBackend`` (tests) and ``CliBackend``
    (production, wrapping ``gh`` and ``aws s3api``) can implement.
    """

    def put_object(
        self, key: str, data: bytes, *, content_type: str, cache_control: str
    ) -> None:
        """Upload ``data`` to ``key`` with an explicit content type and cache policy."""

    def get_object(self, key: str) -> bytes:
        """Read back an uploaded object's bytes, for verification or copying."""

    def delete_object(self, key: str) -> None:
        """Delete a single object."""

    def delete_prefix(self, prefix: str) -> None:
        """Delete every object under ``prefix`` (an orphaned release tree cleanup)."""

    def create_draft_release(self, version: str, archive_path: Path) -> str:
        """Create a draft GitHub Release for ``version``, upload ``archive_path``.

        Returns an opaque release id used by ``finalize_release``/
        ``delete_release``.
        """

    def upload_release_asset(self, release_id: str, key: str, data: bytes) -> None:
        """Upload one additional asset (a primary individual artifact) to the draft."""

    def finalize_release(self, release_id: str) -> None:
        """Make a draft GitHub Release public (un-draft it)."""

    def delete_release(self, release_id: str) -> None:
        """Delete a GitHub Release (cleanup path for a failed publication)."""


def publish_release(plan: PublishPlan, backend: PublishBackend) -> str:
    """Publish ``plan`` to ``backend``, following the design doc's ordering.

    Returns the published version string on success. Raises
    ``PublishError`` (with any compensating cleanup already attempted) on
    any failure.
    """

    version = plan.manifest.release_version
    if not version:
        raise PublishError("cannot publish a plan with no release_version")

    specs = _release_object_specs(plan)
    release_id = None
    latest_overwritten = False

    try:
        release_id = backend.create_draft_release(version, plan.archive_path)
        for spec in specs:
            backend.upload_release_asset(release_id, spec.key, spec.content)

        _upload_and_verify_release_tree(backend, version, specs)
        _upload_and_verify_release_manifest(backend, plan.manifest)

        latest_overwritten = True
        _copy_specs_to_latest(backend, specs)
        _copy_index_to_root(backend, version, plan.manifest.checksums)

        _write_manifest(backend, plan.manifest)
    except Exception as error:
        _cleanup_failed_publication(
            backend,
            version=version,
            release_id=release_id,
            latest_overwritten=latest_overwritten,
            previous_manifest=plan.previous_manifest,
            plan=plan,
            original_error=error,
        )
        raise

    try:
        backend.finalize_release(release_id)
    except Exception as error:
        # S3 has already been fully published: the manifest pointer flip
        # (step 3) succeeded and consumers are correctly served the new
        # version. The design doc's cleanup section only prescribes
        # deleting the draft release when S3 publication itself fails
        # (before the pointer flip); it is silent on this later case. We
        # deliberately do NOT delete or otherwise touch the draft release
        # here: deleting it would not fix anything (S3 is already live and
        # correct) and would instead orphan that correct S3 state with no
        # discoverable GitHub Release at all. The draft is left in place
        # for a human to retry finalization (`gh release edit --draft=false`)
        # or investigate.
        raise PublishError(
            f"S3 publication succeeded but GitHub Release finalization failed "
            f"for version {version}"
        ) from error

    return version


def rollback(
    version: str, backend: PublishBackend, *, target_manifest: Manifest
) -> str:
    """Roll back aliases and complete root metadata to a prior ``version``.

    Re-copies the already-published ``/releases/<version>/`` tree's objects
    into ``/latest/*`` after verifying every source byte against the target
    manifest. It writes target-derived ``SHA256SUMS`` and the complete target
    ``manifest.json`` (with ``latest_version``) strictly last. Never
    re-uploads or rebuilds the immutable tree.
    """

    _validate_rollback_target(version, target_manifest)
    _copy_prefix_to_latest(backend, version, target_manifest.checksums)
    _copy_index_to_root(backend, version, target_manifest.checksums)
    _write_manifest(backend, target_manifest)
    return version


# --- internals -------------------------------------------------------------


def _release_object_specs(plan: PublishPlan) -> tuple[_ObjectSpec, ...]:
    specs = []
    for relative, expected_hash in sorted(plan.manifest.checksums.items()):
        path = plan.dist / relative
        content = path.read_bytes()
        actual_hash = hashlib.sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise PublishError(
                f"local artifact {relative} does not match manifest checksum; "
                "refusing to publish"
            )
        specs.append(
            _ObjectSpec(
                key=relative,
                content=content,
                content_type=_content_type(relative),
                cache_control=_IMMUTABLE_CACHE_CONTROL,
            )
        )
    return tuple(specs)


def _content_type(relative: str) -> str:
    if relative == "index.html":
        return "text/html"
    if relative.endswith(".json"):
        return "application/json"
    return "application/octet-stream"


def _upload_and_verify_release_tree(
    backend: PublishBackend, version: str, specs: Sequence[_ObjectSpec]
) -> None:
    def upload_and_verify(spec: _ObjectSpec) -> None:
        key = f"releases/{version}/{spec.key}"
        backend.put_object(
            key,
            spec.content,
            content_type=spec.content_type,
            cache_control=spec.cache_control,
        )
        readback = backend.get_object(key)
        if hashlib.sha256(readback).hexdigest() != hashlib.sha256(
            spec.content
        ).hexdigest():
            raise PublishError(
                f"read-back verification failed for releases/{version}/{spec.key}"
            )

    _run_parallel_specs(specs, upload_and_verify)


def _copy_specs_to_latest(
    backend: PublishBackend, specs: Sequence[_ObjectSpec]
) -> None:
    def copy_to_latest(spec: _ObjectSpec) -> None:
        key = f"latest/{spec.key}"
        backend.put_object(
            key,
            spec.content,
            content_type=spec.content_type,
            cache_control=_REVALIDATE_CACHE_CONTROL,
        )

    _run_parallel_specs(specs, copy_to_latest)


def _run_parallel_specs(
    specs: Sequence[_ObjectSpec], operation: Callable[[_ObjectSpec], None]
) -> None:
    with ThreadPoolExecutor(max_workers=_S3_MAX_WORKERS) as executor:
        futures = [executor.submit(operation, spec) for spec in specs]
        for future in futures:
            future.result()


def _copy_prefix_to_latest(
    backend: PublishBackend, version: str, checksums: Mapping[str, str]
) -> None:
    """Copy objects named by ``checksums`` from ``releases/<version>/`` to ``latest/``.

    Used both by ``publish_release``'s cleanup-time restoration of
    ``/latest/*`` from the prior version, and by ``rollback``'s primary
    copy step -- the single shared primitive the design doc requires both
    paths to use.
    """

    verified: list[tuple[str, bytes, str]] = []
    for relative, expected_hash in sorted(checksums.items()):
        source_key = f"releases/{version}/{relative}"
        try:
            content = backend.get_object(source_key)
        except Exception as error:
            raise PublishError(f"cannot read immutable target {source_key}") from error
        if hashlib.sha256(content).hexdigest() != expected_hash:
            raise PublishError(
                f"immutable target {source_key} does not match manifest checksum"
            )
        verified.append((relative, content, expected_hash))

    failures: list[str] = []
    for relative, content, expected_hash in verified:
        destination_key = f"latest/{relative}"
        try:
            backend.put_object(
                destination_key,
                content,
                content_type=_content_type(relative),
                cache_control=_REVALIDATE_CACHE_CONTROL,
            )
            readback = backend.get_object(destination_key)
            if hashlib.sha256(readback).hexdigest() != expected_hash:
                raise PublishError(
                    f"read-back verification failed while restoring latest/{relative} "
                    f"from releases/{version}/"
                )
        except Exception as error:
            failures.append(f"latest/{relative}: {error}")

    if failures:
        raise PublishError(
            "failed to restore one or more latest objects: " + "; ".join(failures)
        )


def _copy_index_to_root(
    backend: PublishBackend, version: str, checksums: Mapping[str, str]
) -> None:
    """Copy the release index page to the public root, verifying its bytes."""

    expected_hash = checksums.get("index.html")
    if expected_hash is None:
        backend.delete_object("index.html")
        return
    source_key = f"releases/{version}/index.html"
    try:
        content = backend.get_object(source_key)
    except Exception as error:
        raise PublishError(f"cannot read immutable target {source_key}") from error
    if hashlib.sha256(content).hexdigest() != expected_hash:
        raise PublishError(
            f"immutable target {source_key} does not match manifest checksum"
        )
    backend.put_object(
        "index.html",
        content,
        content_type="text/html",
        cache_control=_REVALIDATE_CACHE_CONTROL,
    )
    if backend.get_object("index.html") != content:
        raise PublishError(
            "read-back verification failed while writing root index.html"
        )


def _write_manifest(backend: PublishBackend, manifest: Manifest) -> None:
    """Write the root ``SHA256SUMS`` and then ``manifest.json`` pointer.

    ``SHA256SUMS`` is written first and ``manifest.json`` strictly last, per
    the design doc's "the package stage instead produces the artifacts and
    ``SHA256SUMS`` first, then writes ``manifest.json`` last" and "as the
    final step, write ``/manifest.json``". This ordering matters for
    failure safety: ``publish_release``'s cleanup path treats *any*
    exception from this function as "the pointer was not yet flipped, safe
    to fully delete the new release tree and restore ``/latest/*``". That
    is only true if ``manifest.json`` -- the actual pointer -- is the very
    last write, with nothing else in this function able to fail afterward.
    Writing ``manifest.json`` first (the previous, incorrect ordering)
    could let a subsequent ``SHA256SUMS`` failure unwind into cleanup while
    the root pointer already named the new (about to be deleted) version.
    """

    sums_body = _sha256sums_body(manifest)
    backend.put_object(
        "SHA256SUMS",
        sums_body,
        content_type="text/plain",
        cache_control=_REVALIDATE_CACHE_CONTROL,
    )
    body = _manifest_json_bytes(manifest, latest_version=manifest.release_version)
    backend.put_object(
        "manifest.json",
        body,
        content_type="application/json",
        cache_control=_REVALIDATE_CACHE_CONTROL,
    )


def _upload_and_verify_release_manifest(
    backend: PublishBackend, manifest: Manifest
) -> None:
    version = manifest.release_version
    if not version:
        raise PublishError(
            "cannot publish immutable release manifest without a version"
        )
    key = f"releases/{version}/manifest.json"
    body = _manifest_json_bytes(manifest)
    backend.put_object(
        key,
        body,
        content_type="application/json",
        cache_control=_IMMUTABLE_CACHE_CONTROL,
    )
    if backend.get_object(key) != body:
        raise PublishError(
            f"read-back verification failed for immutable release manifest {key}"
        )


def _manifest_json_bytes(
    manifest: Manifest, *, latest_version: str | None = None
) -> bytes:
    payload = manifest.to_json_dict()
    if latest_version is not None:
        payload = {**payload, "latest_version": latest_version}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256sums_body(manifest: Manifest) -> bytes:
    lines = [
        f"{digest}  {relative}\n"
        for relative, digest in sorted(manifest.checksums.items())
    ]
    return "".join(lines).encode("utf-8")


def _validate_rollback_target(version: str, manifest: Manifest) -> None:
    if not version or manifest.release_version != version:
        raise PublishError(
            f"rollback version {version!r} does not match target manifest "
            f"release_version {manifest.release_version!r}"
        )
    if manifest.schema_version != "1":
        raise PublishError("target manifest has an unsupported schema_version")
    for name, value in (
        ("content_fingerprint", manifest.content_fingerprint),
        ("policy_fingerprint", manifest.policy_fingerprint),
        ("sha256sums_sha256", manifest.sha256sums_sha256),
    ):
        if not _is_sha256(value):
            raise PublishError(f"target manifest has an invalid {name}")
    if not manifest.checksums:
        raise PublishError("target manifest has no artifact checksums")
    archive_fields = (
        ("archive_filename", manifest.archive_filename),
        ("archive_sha256", manifest.archive_sha256),
        ("archive_size_bytes", manifest.archive_size_bytes),
    )
    for field_name, value in archive_fields:
        if value is None:
            raise PublishError(
                f"target manifest is incomplete for rollback: missing {field_name}"
            )
    archive_filename = manifest.archive_filename
    archive_sha256 = manifest.archive_sha256
    archive_size_bytes = manifest.archive_size_bytes
    archive_path = PurePosixPath(archive_filename)
    if (
        not archive_filename
        or archive_path.is_absolute()
        or ".." in archive_path.parts
        or archive_path.name != archive_filename
    ):
        raise PublishError("target manifest has an invalid archive_filename")
    if not _is_sha256(archive_sha256):
        raise PublishError("target manifest has an invalid archive_sha256")
    if (
        not isinstance(archive_size_bytes, int)
        or isinstance(archive_size_bytes, bool)
        or archive_size_bytes < 0
    ):
        raise PublishError("target manifest has an invalid archive_size_bytes")
    if set(manifest.artifact_sizes) != set(manifest.checksums):
        raise PublishError(
            "target manifest artifact_sizes and checksums name different paths"
        )
    for relative, digest in manifest.checksums.items():
        path = PurePosixPath(relative)
        if (
            not relative
            or path.is_absolute()
            or ".." in path.parts
            or str(path) != relative
        ):
            raise PublishError(
                f"target manifest has an unsafe artifact path: {relative}"
            )
        if not _is_sha256(digest):
            raise PublishError(
                f"target manifest has an invalid checksum for {relative}"
            )
        size = manifest.artifact_sizes[relative]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise PublishError(f"target manifest has an invalid size for {relative}")
    if hashlib.sha256(_sha256sums_body(manifest)).hexdigest() != (
        manifest.sha256sums_sha256
    ):
        raise PublishError(
            "target manifest SHA256SUMS hash does not match its artifact checksums"
        )


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _cleanup_failed_publication(
    backend: PublishBackend,
    *,
    version: str,
    release_id: str | None,
    latest_overwritten: bool,
    previous_manifest: Manifest | None,
    plan: PublishPlan,
    original_error: Exception,
) -> None:
    """Best-effort compensating cleanup for a publication that failed before
    the manifest pointer write completed.

    Never raises on cleanup problems by itself -- instead re-raises a
    ``PublishError`` chained from ``original_error`` describing what
    cleanup did or did not manage to do, so the caller always learns both
    the original failure and the cleanup outcome. Cleanup never writes
    ``manifest.json`` and never finalizes a GitHub Release.
    """

    cleanup_problems: list[str] = []

    if release_id is not None:
        try:
            backend.delete_release(release_id)
        except Exception as cleanup_error:
            cleanup_problems.append(
                f"failed to delete draft GitHub Release {release_id}: {cleanup_error}"
            )

    try:
        backend.delete_prefix(f"releases/{version}/")
    except Exception as cleanup_error:
        cleanup_problems.append(
            f"failed to delete orphaned S3 tree releases/{version}/: {cleanup_error}"
        )

    if latest_overwritten:
        if previous_manifest is not None:
            try:
                _copy_prefix_to_latest(
                    backend,
                    previous_manifest.release_version,
                    previous_manifest.checksums,
                )
                _copy_index_to_root(
                    backend,
                    previous_manifest.release_version,
                    previous_manifest.checksums,
                )
            except Exception as cleanup_error:
                cleanup_problems.append(
                    "failed to restore /latest/* from prior version "
                    f"{previous_manifest.release_version}: {cleanup_error}"
                )
        else:
            try:
                backend.delete_object("index.html")
            except Exception as cleanup_error:
                cleanup_problems.append(
                    "failed to remove root index.html after an initial-release "
                    f"failure: {cleanup_error}"
                )
            cleanup_problems.append(
                "/latest/* objects were overwritten but no previous manifest "
                "was available to restore from"
            )

    if cleanup_problems:
        raise PublishError(
            f"publication of version {version} failed ({original_error}); "
            "cleanup encountered problems and may have left an orphaned "
            "release path or inconsistent /latest/* aliases -- the manifest "
            "pointer was NOT changed: " + "; ".join(cleanup_problems)
        ) from original_error

    raise PublishError(
        f"publication of version {version} failed and was cleaned up "
        f"(draft release and S3 release tree deleted, /latest/* restored if "
        f"needed): {original_error}"
    ) from original_error


# --- test double -------------------------------------------------------


@dataclass
class _StoredObject:
    content: bytes
    content_type: str
    cache_control: str


class FakeBackend:
    """In-memory ``PublishBackend`` test double with injectable failure points.

    Mirrors ``tests/test_generate.py``'s ``FakeRunner``/
    ``tests/test_pipeline.py``'s ``_FakeToolExecutor`` style: a plain
    in-process fake standing in for the native-tool/HTTP boundary, with
    simple attributes a test sets before calling ``publish_release``/
    ``rollback`` to force a specific step to fail.
    """

    def __init__(self) -> None:
        self.objects: dict[str, _StoredObject] = {}
        self.put_log: list[tuple[str, str]] = []
        self.deleted_prefixes: list[str] = []
        self.created_release_id: str | None = None
        self.draft_created_index: int | None = None
        self.finalized_release_id: str | None = None
        self.finalize_index: int | None = None
        self.deleted_release_id: str | None = None

        # Failure injection knobs.
        self.fail_put_key: str | None = None
        self.corrupt_readback_key: str | None = None
        self.fail_delete_prefix: bool = False
        self.fail_finalize: bool = False
        self.fail_create_release: bool = False
        self.secret_marker: str | None = None

        self._op_count = 0
        self._release_counter = 0

    def _tick(self) -> int:
        self._op_count += 1
        return self._op_count

    def put_object(
        self, key: str, data: bytes, *, content_type: str, cache_control: str
    ) -> None:
        self._tick()
        self.put_log.append((self._op_count, key))
        if self.fail_put_key == key:
            detail = " [redacted credentials]" if self.secret_marker else ""
            raise RuntimeError(f"simulated put_object failure for {key}{detail}")
        self.objects[key] = _StoredObject(data, content_type, cache_control)

    def get_object(self, key: str) -> bytes:
        if key not in self.objects:
            raise KeyError(f"no such object: {key}")
        content = self.objects[key].content
        if self.corrupt_readback_key == key:
            return content + b"\x00corrupt"
        return content

    def delete_object(self, key: str) -> None:
        self.objects.pop(key, None)

    def delete_prefix(self, prefix: str) -> None:
        self.deleted_prefixes.append(prefix)
        if self.fail_delete_prefix:
            raise RuntimeError(f"simulated delete_prefix failure for {prefix}")
        for key in [k for k in self.objects if k.startswith(prefix)]:
            del self.objects[key]

    def create_draft_release(self, version: str, archive_path: Path) -> str:
        self.draft_created_index = self._tick()
        if self.fail_create_release:
            raise RuntimeError(
                f"simulated create_draft_release failure for {version}"
            )
        self._release_counter += 1
        release_id = f"draft-{self._release_counter}-{version}"
        self.created_release_id = release_id
        return release_id

    def upload_release_asset(self, release_id: str, key: str, data: bytes) -> None:
        self._tick()
        self.put_log.append((self._op_count, key))

    def finalize_release(self, release_id: str) -> None:
        self.finalize_index = self._tick()
        if self.fail_finalize:
            raise RuntimeError(
                f"simulated finalize_release failure for {release_id}"
            )
        self.finalized_release_id = release_id

    def delete_release(self, release_id: str) -> None:
        self.deleted_release_id = release_id


# --- production backend -------------------------------------------------


@dataclass(frozen=True)
class YandexS3Credentials:
    """Yandex Object Storage connection details, treated as external secrets.

    Only the static key pair comes from the runtime environment. The bucket
    and endpoint are fixed by the production deployment, preventing a
    credentialed publication from being redirected through configuration.
    """

    access_key_id: str
    secret_access_key: str
    bucket: str = field(default="routing.akent.site", init=False)
    endpoint_url: str = field(default="https://storage.yandexcloud.net", init=False)

    def __repr__(self) -> str:  # pragma: no cover -- trivial formatting
        return (
            f"YandexS3Credentials(bucket={self.bucket!r}, "
            f"endpoint_url={self.endpoint_url!r}, "
            "access_key_id=<redacted>, secret_access_key=<redacted>)"
        )

    __str__ = __repr__

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "YandexS3Credentials":
        try:
            return cls(
                access_key_id=env["YANDEX_S3_ACCESS_KEY_ID"],
                secret_access_key=env["YANDEX_S3_SECRET_ACCESS_KEY"],
            )
        except KeyError as error:
            # Report only the missing variable's name -- never dump the
            # environment, which could contain unrelated secret values.
            raise PublishError(
                f"missing required Yandex S3 environment variable: {error}"
            ) from error


class CliBackend:
    """Production ``PublishBackend`` wrapping ``gh`` and ``aws s3api``.

    The ``gh``-wrapping methods (``create_draft_release``,
    ``upload_release_asset``, ``finalize_release``, ``delete_release``) go
    through ``ToolRunner`` (the same argv-only, no-shell boundary
    ``generate.py``/``validate.py`` use for native tools). ``_run_aws`` (used
    by the S3 methods) instead calls ``subprocess.run`` directly, because it
    needs to pass Yandex credentials via ``env=`` -- ``ToolRunner.run`` has no
    ``env`` parameter -- but it still follows the same argv-only,
    ``shell=False`` discipline: an explicit list of arguments, never a shell
    command string, so credentials cannot leak through shell history or
    shell expansion either way.

    Credentials are held only as constructor fields, passed to subprocesses
    via the AWS CLI's conventional ``AWS_ACCESS_KEY_ID`` and
    ``AWS_SECRET_ACCESS_KEY`` environment variables, never as a literal argv
    element (which could appear in process listings), and
    never interpolated into an exception message or log line anywhere in
    this class. Exceptions raised here include tool argv and stdout/stderr
    (via ``ToolError``) but not the credential-bearing environment.
    """

    def __init__(
        self,
        *,
        yandex_s3: YandexS3Credentials,
        repo: str,
        runner: ToolRunner | None = None,
        gh: str = "gh",
        aws: str = "aws",
        workdir: Path | None = None,
        aws_subprocess_runner=subprocess.run,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._yandex_s3 = yandex_s3
        self._repo = repo
        self._runner = runner or ToolRunner()
        self._gh = gh
        self._aws = aws
        self._workdir = Path(workdir) if workdir is not None else Path.cwd()
        # Injectable only so tests can exercise _run_aws's callers (notably
        # delete_prefix's list-objects-v2 pagination loop) without shelling
        # out to a real `aws` binary; production code never overrides this.
        self._aws_subprocess_runner = aws_subprocess_runner
        self._monotonic = monotonic

    def _aws_env(self) -> dict[str, str]:
        return {
            **{
                key: value
                for key, value in os.environ.items()
                if not key.startswith("AWS_")
            },
            "AWS_ACCESS_KEY_ID": self._yandex_s3.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self._yandex_s3.secret_access_key,
            "AWS_DEFAULT_REGION": "ru-central1",
            "AWS_REGION": "ru-central1",
        }

    def _run_aws(self, argv: Sequence[str]) -> str:
        # Deliberately bypasses ToolRunner: ToolRunner.run(argv, cwd) has no
        # env= parameter, and the AWS CLI needs AWS_ACCESS_KEY_ID/
        # AWS_SECRET_ACCESS_KEY passed via the environment (see _aws_env).
        # This still follows the same argv-only, shell=False discipline as
        # ToolRunner -- an explicit argument list, never a shell string.
        command = [
            self._aws,
            "s3api",
            *argv,
            "--endpoint-url",
            self._yandex_s3.endpoint_url,
        ]
        operation = argv[0] if argv else "unknown"
        key = argv[argv.index("--key") + 1] if "--key" in argv else "-"
        started_at = self._monotonic()
        try:
            completed = self._aws_subprocess_runner(
                command,
                cwd=self._workdir,
                env=self._aws_env(),
                capture_output=True,
                check=False,
                shell=False,
                text=False,
                timeout=60.0,
            )
            if completed.returncode != 0:
                stderr = completed.stderr.decode("utf-8", errors="replace")
                raise PublishError(
                    f"aws s3api {' '.join(argv[:2])} failed with status "
                    f"{completed.returncode}: {stderr}"
                )
            return completed.stdout
        finally:
            _log_s3_timing(operation, key, self._monotonic() - started_at)

    def put_object(
        self, key: str, data: bytes, *, content_type: str, cache_control: str
    ) -> None:
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(data)
            body_path = handle.name
        try:
            self._run_aws(
                [
                    "put-object",
                    "--bucket",
                    self._yandex_s3.bucket,
                    "--key",
                    key,
                    "--body",
                    body_path,
                    "--content-type",
                    content_type,
                    "--cache-control",
                    cache_control,
                ]
            )
        finally:
            Path(body_path).unlink(missing_ok=True)

    def get_object(self, key: str) -> bytes:
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            output_path = handle.name
        try:
            self._run_aws(
                [
                    "get-object",
                    "--bucket",
                    self._yandex_s3.bucket,
                    "--key",
                    key,
                    output_path,
                ]
            )
            return Path(output_path).read_bytes()
        finally:
            Path(output_path).unlink(missing_ok=True)

    def delete_object(self, key: str) -> None:
        self._run_aws(
            ["delete-object", "--bucket", self._yandex_s3.bucket, "--key", key]
        )

    def delete_prefix(self, prefix: str) -> None:
        # list-objects-v2 caps Contents at 1000 keys per call and signals
        # truncation via IsTruncated/NextContinuationToken; a release tree
        # exceeding 1000 objects would otherwise leave the remainder as a
        # silently orphaned partial tree in exactly this cleanup path. We
        # collect every key across every page before deleting anything, so
        # the delete loop below always sees the complete set.
        keys: list[str] = []
        continuation_token: str | None = None
        while True:
            argv = [
                "list-objects-v2",
                "--bucket",
                self._yandex_s3.bucket,
                "--prefix",
                prefix,
                "--output",
                "json",
            ]
            if continuation_token is not None:
                argv.extend(["--continuation-token", continuation_token])
            listing = self._run_aws(argv)
            payload = json.loads(listing) if listing else {}
            keys.extend(item["Key"] for item in payload.get("Contents", []))
            if not payload.get("IsTruncated"):
                break
            continuation_token = payload.get("NextContinuationToken")
            if continuation_token is None:
                break
        for object_key in keys:
            self.delete_object(object_key)

    def create_draft_release(self, version: str, archive_path: Path) -> str:
        self._runner.run(
            [
                self._gh,
                "release",
                "create",
                version,
                str(archive_path),
                "--repo",
                self._repo,
                "--draft",
                "--title",
                version,
                "--notes",
                f"Routing release {version}",
            ],
            cwd=self._workdir,
        )
        return version

    def upload_release_asset(self, release_id: str, key: str, data: bytes) -> None:
        asset_name = key.replace("/", "__")
        with tempfile.NamedTemporaryFile(
            delete=False, suffix=f"-{asset_name}"
        ) as handle:
            handle.write(data)
            asset_path = handle.name
        try:
            self._runner.run(
                [
                    self._gh,
                    "release",
                    "upload",
                    release_id,
                    f"{asset_path}#{asset_name}",
                    "--repo",
                    self._repo,
                    "--clobber",
                ],
                cwd=self._workdir,
            )
        finally:
            Path(asset_path).unlink(missing_ok=True)

    def finalize_release(self, release_id: str) -> None:
        self._runner.run(
            [
                self._gh,
                "release",
                "edit",
                release_id,
                "--repo",
                self._repo,
                "--draft=false",
            ],
            cwd=self._workdir,
        )

    def delete_release(self, release_id: str) -> None:
        self._runner.run(
            [
                self._gh,
                "release",
                "delete",
                release_id,
                "--repo",
                self._repo,
                "--yes",
            ],
            cwd=self._workdir,
        )


def _log_s3_timing(operation: str, key: str, duration_seconds: float) -> None:
    """Write a best-effort, credential-safe AWS operation duration to stdout."""

    try:
        print(
            "ru-routing: s3 "
            f"operation={operation} key={key} duration_seconds={duration_seconds:.3f}"
        )
    except OSError:
        # A logging failure must not change publication state after the
        # manifest pointer write has succeeded.
        pass
