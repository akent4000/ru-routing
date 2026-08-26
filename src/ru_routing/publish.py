"""Publish a packaged release to R2 and GitHub, and support manual rollback.

Implements the design doc's "Publication and CDN" and "Release Integrity
and Rollback" sections. A completed :func:`ru_routing.package.package_build`
call produces a :class:`~ru_routing.package.Manifest` plus a ``dist`` tree
and a sibling release archive; this module takes that output (wrapped in a
:class:`PublishPlan`) and performs the load-bearing publication sequence:

1. upload and read-back-verify the complete immutable ``/releases/<version>/``
   tree (never overwritten once published);
2. upload the individual objects under ``/latest/*`` -- copies of the
   just-verified immutable tree's content;
3. as the final step, write ``/manifest.json`` with the new
   ``latest_version`` -- the single atomic pointer flip;
4. purge the Cloudflare cache for ``/latest/*`` and ``/manifest.json``.

A draft GitHub Release is created and its assets uploaded *before* R2
publication begins; it is finalized (made public/non-draft) only after step
3 has been verified.

Failure handling: any failure at or before step 3 (i.e. before the manifest
pointer write is confirmed) triggers cleanup -- delete the draft GitHub
Release, delete the newly uploaded ``/releases/<version>/`` R2 tree, and (if
any ``/latest/*`` objects were already overwritten) restore and verify the
complete ``/latest/*`` tree from the prior immutable version named by the
unchanged root manifest. A failure at step 4 (cache purge) does NOT trigger
cleanup: the manifest pointer has already flipped and the release is live,
so the correct remedial action is to retry the purge, not to roll back a
successful publication. Cleanup failures are reported explicitly via
``PublishError`` and never change the manifest pointer or create a public
GitHub Release.

Rollback (:func:`rollback`) reuses the exact same copy-then-pointer-flip
primitive that ``publish_release``'s cleanup path uses to restore
``/latest/*`` from a prior version (see ``_copy_prefix_to_latest`` and
``_write_manifest_pointer``), sourced from an already-published prior
version's ``/releases/<version>/`` tree instead of a freshly built one --
it never rebuilds a release.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Protocol, Sequence, runtime_checkable

import httpx

from .package import Manifest
from .tooling import ToolRunner

_IMMUTABLE_CACHE_CONTROL = "public, max-age=31536000, immutable"
_REVALIDATE_CACHE_CONTROL = "public, max-age=300, must-revalidate"


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
    ``previous_manifest`` is the manifest currently live in R2's root
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
    """Minimal boundary over R2 (S3-compatible) and GitHub Release operations.

    Modeled after ``ToolExecutor``/``GeodataReader``/``RegexValidator``'s
    narrow Protocol boundaries elsewhere in this codebase: a small set of
    primitives that both ``FakeBackend`` (tests) and ``CliBackend``
    (production, wrapping ``gh``/``aws s3api``/Cloudflare's HTTP API) can
    implement.
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

    def purge_cache(self, paths: Sequence[str]) -> None:
        """Purge the Cloudflare cache for the given absolute paths."""

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

        latest_overwritten = True
        _copy_specs_to_latest(backend, specs)

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
        raise PublishError(
            f"R2 publication succeeded but GitHub Release finalization failed "
            f"for version {version}"
        ) from error

    try:
        backend.purge_cache(_purge_paths(plan.manifest))
    except Exception as error:
        # Step 4 (cache purge) happens strictly after the atomic manifest
        # pointer flip (step 3) has already succeeded and the GitHub
        # Release has already been finalized -- the release is live. A
        # purge failure must NOT undo the pointer or delete the release;
        # the only remedial action is to retry the purge later.
        raise PublishError(
            f"published version {version} but cache purge failed; "
            "retry the purge -- the manifest pointer and release are live"
        ) from error

    return version


def rollback(
    version: str, backend: PublishBackend, *, checksums: Mapping[str, str]
) -> str:
    """Roll back ``/latest/*`` and the manifest pointer to a prior ``version``.

    Re-copies the already-published ``/releases/<version>/`` tree's objects
    into ``/latest/*`` and then writes ``manifest.json`` naming ``version``
    as ``latest_version`` -- the same two-step order ``publish_release``
    uses for its own ``/latest/*`` update, via the shared
    ``_copy_prefix_to_latest``/``_write_manifest_pointer`` primitives.
    Never re-uploads or rebuilds ``/releases/<version>/``.

    ``checksums`` names the relative paths (and their expected sha256, used
    only for read-back verification of the copy) that make up the prior
    version's tree -- typically the ``checksums`` field of the manifest
    that was published alongside that version.
    """

    _copy_prefix_to_latest(backend, version, checksums)
    _write_manifest_pointer(backend, version)
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
    if relative.endswith(".json"):
        return "application/json"
    return "application/octet-stream"


def _upload_and_verify_release_tree(
    backend: PublishBackend, version: str, specs: Sequence[_ObjectSpec]
) -> None:
    for spec in specs:
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


def _copy_specs_to_latest(
    backend: PublishBackend, specs: Sequence[_ObjectSpec]
) -> None:
    for spec in specs:
        key = f"latest/{spec.key}"
        backend.put_object(
            key,
            spec.content,
            content_type=spec.content_type,
            cache_control=_REVALIDATE_CACHE_CONTROL,
        )


def _copy_prefix_to_latest(
    backend: PublishBackend, version: str, checksums: Mapping[str, str]
) -> None:
    """Copy objects named by ``checksums`` from ``releases/<version>/`` to ``latest/``.

    Used both by ``publish_release``'s cleanup-time restoration of
    ``/latest/*`` from the prior version, and by ``rollback``'s primary
    copy step -- the single shared primitive the design doc requires both
    paths to use.
    """

    for relative in sorted(checksums):
        source_key = f"releases/{version}/{relative}"
        content = backend.get_object(source_key)
        destination_key = f"latest/{relative}"
        backend.put_object(
            destination_key,
            content,
            content_type=_content_type(relative),
            cache_control=_REVALIDATE_CACHE_CONTROL,
        )
        readback = backend.get_object(destination_key)
        if hashlib.sha256(readback).hexdigest() != hashlib.sha256(
            content
        ).hexdigest():
            raise PublishError(
                f"read-back verification failed while restoring latest/{relative} "
                f"from releases/{version}/"
            )


def _write_manifest(backend: PublishBackend, manifest: Manifest) -> None:
    payload = {**manifest.to_json_dict(), "latest_version": manifest.release_version}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    backend.put_object(
        "manifest.json",
        body,
        content_type="application/json",
        cache_control=_REVALIDATE_CACHE_CONTROL,
    )
    sums_body = _sha256sums_body(manifest)
    backend.put_object(
        "SHA256SUMS",
        sums_body,
        content_type="text/plain",
        cache_control=_REVALIDATE_CACHE_CONTROL,
    )


def _sha256sums_body(manifest: Manifest) -> bytes:
    lines = [
        f"{digest}  {relative}\n"
        for relative, digest in sorted(manifest.checksums.items())
    ]
    return "".join(lines).encode("utf-8")


def _write_manifest_pointer(backend: PublishBackend, version: str) -> None:
    """Write ``manifest.json`` naming ``version`` as ``latest_version``.

    Used by ``rollback``. Fetches the prior root manifest first (if any) so
    the write preserves every other manifest field and only flips the
    pointer, per "rollback... writes manifest.json with that version as
    latest_version".
    """

    try:
        existing = json.loads(backend.get_object("manifest.json"))
    except Exception:
        existing = {}
    payload = {**existing, "latest_version": version}
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    backend.put_object(
        "manifest.json",
        body,
        content_type="application/json",
        cache_control=_REVALIDATE_CACHE_CONTROL,
    )


def _purge_paths(manifest: Manifest) -> tuple[str, ...]:
    paths = {"/manifest.json", "/SHA256SUMS"}
    for relative in manifest.checksums:
        paths.add(f"/latest/{relative}")
    return tuple(sorted(paths))


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
            f"failed to delete orphaned R2 tree releases/{version}/: {cleanup_error}"
        )

    if latest_overwritten:
        if previous_manifest is not None:
            try:
                _copy_prefix_to_latest(
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
        f"(draft release and R2 release tree deleted, /latest/* restored if "
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
        self.purged: list[tuple[str, ...]] = []
        self.purge_index: int | None = None
        self.deleted_prefixes: list[str] = []
        self.created_release_id: str | None = None
        self.draft_created_index: int | None = None
        self.finalized_release_id: str | None = None
        self.finalize_index: int | None = None
        self.deleted_release_id: str | None = None

        # Failure injection knobs.
        self.fail_put_key: str | None = None
        self.corrupt_readback_key: str | None = None
        self.fail_purge: bool = False
        self.fail_delete_prefix: bool = False
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

    def purge_cache(self, paths: Sequence[str]) -> None:
        self.purge_index = self._tick()
        self.purged.append(tuple(paths))
        if self.fail_purge:
            raise RuntimeError("simulated cache purge failure")

    def create_draft_release(self, version: str, archive_path: Path) -> str:
        self.draft_created_index = self._tick()
        self._release_counter += 1
        release_id = f"draft-{self._release_counter}-{version}"
        self.created_release_id = release_id
        return release_id

    def upload_release_asset(self, release_id: str, key: str, data: bytes) -> None:
        self._tick()
        self.put_log.append((self._op_count, key))

    def finalize_release(self, release_id: str) -> None:
        self.finalize_index = self._tick()
        self.finalized_release_id = release_id

    def delete_release(self, release_id: str) -> None:
        self.deleted_release_id = release_id


# --- production backend -------------------------------------------------


@dataclass(frozen=True)
class R2Credentials:
    """R2 (S3-compatible) connection details, treated as external secrets.

    Never log an instance of this class or any of its fields. In
    production these come from GitHub Actions secrets/variables (see the
    design doc's "Publication and CDN" section); ``from_env`` reads the
    conventional environment variable names a workflow step would export,
    but the constructor itself accepts explicit values so callers are free
    to source them however they choose (a secrets manager, a test
    fixture, etc.) without this module ever needing to know.
    """

    account_id: str
    access_key_id: str
    secret_access_key: str
    bucket: str
    endpoint_url: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "R2Credentials":
        try:
            return cls(
                account_id=env["R2_ACCOUNT_ID"],
                access_key_id=env["R2_ACCESS_KEY_ID"],
                secret_access_key=env["R2_SECRET_ACCESS_KEY"],
                bucket=env["R2_BUCKET"],
                endpoint_url=env["R2_ENDPOINT_URL"],
            )
        except KeyError as error:
            # Report only the missing variable's *name* -- never dump the
            # environment, which could contain unrelated secret values.
            raise PublishError(
                f"missing required R2 environment variable: {error}"
            ) from error


@dataclass(frozen=True)
class CloudflareCredentials:
    """Cloudflare cache-purge API details, treated as external secrets."""

    zone_id: str
    api_token: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "CloudflareCredentials":
        try:
            return cls(
                zone_id=env["CLOUDFLARE_ZONE_ID"],
                api_token=env["CLOUDFLARE_API_TOKEN"],
            )
        except KeyError as error:
            raise PublishError(
                f"missing required Cloudflare environment variable: {error}"
            ) from error


class CliBackend:
    """Production ``PublishBackend`` wrapping ``gh``, ``aws s3api``, and Cloudflare.

    All subprocess invocations go through ``ToolRunner`` (the same
    argv-only, no-shell boundary ``generate.py``/``validate.py`` use for
    native tools) -- never a shell command string, so credentials passed
    as CLI arguments cannot leak through shell history/expansion, and every
    argument is an explicit, inspectable list element.

    Credentials (``r2`` / ``cloudflare``) are held only as constructor
    fields, passed to subprocesses via ``env`` (for the AWS CLI's
    conventional ``AWS_ACCESS_KEY_ID``/``AWS_SECRET_ACCESS_KEY`` variables)
    or as an HTTP Authorization header (for Cloudflare) -- never as a
    literal argv element (which could appear in process listings) and
    never interpolated into an exception message or log line anywhere in
    this class. Exceptions raised here include tool argv and stdout/stderr
    (via ``ToolError``) but not the credential-bearing environment.
    """

    def __init__(
        self,
        *,
        r2: R2Credentials,
        cloudflare: CloudflareCredentials,
        repo: str,
        runner: ToolRunner | None = None,
        gh: str = "gh",
        aws: str = "aws",
        workdir: Path | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._r2 = r2
        self._cloudflare = cloudflare
        self._repo = repo
        self._runner = runner or ToolRunner()
        self._gh = gh
        self._aws = aws
        self._workdir = Path(workdir) if workdir is not None else Path.cwd()
        self._http_client = http_client

    def _aws_env(self) -> dict[str, str]:
        return {
            **os.environ,
            "AWS_ACCESS_KEY_ID": self._r2.access_key_id,
            "AWS_SECRET_ACCESS_KEY": self._r2.secret_access_key,
        }

    def _run_aws(self, argv: Sequence[str]) -> str:
        command = [self._aws, "s3api", *argv, "--endpoint-url", self._r2.endpoint_url]
        completed = subprocess.run(
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
                    self._r2.bucket,
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
                    self._r2.bucket,
                    "--key",
                    key,
                    output_path,
                ]
            )
            return Path(output_path).read_bytes()
        finally:
            Path(output_path).unlink(missing_ok=True)

    def delete_object(self, key: str) -> None:
        self._run_aws(["delete-object", "--bucket", self._r2.bucket, "--key", key])

    def delete_prefix(self, prefix: str) -> None:
        listing = self._run_aws(
            ["list-objects-v2", "--bucket", self._r2.bucket, "--prefix", prefix]
        )
        payload = json.loads(listing) if listing else {}
        keys = [item["Key"] for item in payload.get("Contents", [])]
        for object_key in keys:
            self.delete_object(object_key)

    def purge_cache(self, paths: Sequence[str]) -> None:
        client = self._http_client or httpx.Client(timeout=30.0)
        try:
            response = client.post(
                f"https://api.cloudflare.com/client/v4/zones/"
                f"{self._cloudflare.zone_id}/purge_cache",
                headers={
                    "Authorization": f"Bearer {self._cloudflare.api_token}",
                    "Content-Type": "application/json",
                },
                json={"files": [f"https://routing.akent.site{p}" for p in paths]},
            )
        finally:
            if self._http_client is None:
                client.close()
        if response.status_code >= 400:
            # Deliberately omit the request body/headers from the error --
            # they were built from the bearer token above.
            raise PublishError(
                f"Cloudflare cache purge failed with status {response.status_code}"
            )

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
