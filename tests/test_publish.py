"""State-machine tests for R2/GitHub publication and rollback.

Exercises ``publish_release``/``rollback`` against an in-memory
``FakeBackend`` implementing the ``PublishBackend`` protocol, per the design
doc's "Publication and CDN" and "Release Integrity and Rollback" sections:

- draft GitHub Release created and assets uploaded before R2 publication;
- immutable ``/releases/<version>/`` tree uploaded and read-back-verified
  first;
- ``/latest/*`` objects copied from the just-verified tree second;
- ``/manifest.json`` written last -- the single atomic pointer flip;
- Cloudflare cache purge for ``/latest/*`` and ``/manifest.json`` fourth;
- the GitHub Release is finalized (un-drafted) only after the manifest
  pointer write is verified;
- any failure before the manifest pointer write triggers cleanup: delete
  the draft GitHub Release, delete the newly uploaded
  ``/releases/<version>/`` tree, and -- if any ``/latest/*`` objects were
  already overwritten -- restore and verify ``/latest/*`` from the prior
  version named by the (unchanged) root manifest;
- cleanup never changes the manifest pointer and never creates a public
  GitHub Release, even when cleanup itself fails;
- ``rollback`` re-copies a prior immutable version's tree into ``/latest/*``
  and writes ``manifest.json`` last, reusing the same primitive
  ``publish_release`` uses for its own ``/latest/*`` update step.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import pytest

from ru_routing.package import Manifest
from ru_routing.publish import (
    CliBackend,
    CloudflareCredentials,
    FakeBackend,
    PublishBackend,
    PublishError,
    PublishPlan,
    R2Credentials,
    publish_release,
    rollback,
)

_RELATIVE_PATHS = ("xray/geoip.dat", "sing-box/lite/example.json")


def _content_for(version: str, relative: str) -> bytes:
    return f"{version}:{relative}".encode("utf-8")


def _manifest(version: str, *, checksums=None) -> Manifest:
    checksums = checksums or {
        relative: hashlib.sha256(_content_for(version, relative)).hexdigest()
        for relative in _RELATIVE_PATHS
    }
    artifact_sizes = {
        key: len(_content_for(version, key)) for key in checksums
    }
    sums = "".join(
        f"{digest}  {relative}\n"
        for relative, digest in sorted(checksums.items())
    ).encode()
    return Manifest(
        schema_version="1",
        release_version=version,
        content_fingerprint="c" * 64,
        policy_fingerprint="d" * 64,
        sources=(),
        category_counts={"lite:blocked": 3},
        total_size_bytes=123,
        artifact_sizes=artifact_sizes,
        checksums=checksums,
        sha256sums_sha256=hashlib.sha256(sums).hexdigest(),
        tool_versions={},
        conflict_statistics={"overlaps_before": 0, "overlaps_after": 0, "resolved": 0},
        built_at="2026-08-25T00:00:00+00:00",
        archive_filename=f"{version}.tar.gz",
        archive_sha256="f" * 64,
        archive_size_bytes=42,
    )


def _write_dist(tmp_path, manifest: Manifest):
    dist = tmp_path / "dist"
    dist.mkdir()
    version = manifest.release_version
    for relative in manifest.checksums:
        path = dist / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_content_for(version, relative))
    (dist / "SHA256SUMS").write_text("fake\n", encoding="utf-8")
    (dist / "manifest.json").write_text(
        json.dumps(manifest.to_json_dict()), encoding="utf-8"
    )
    archive_path = tmp_path / manifest.archive_filename
    archive_path.write_bytes(b"archive-bytes")
    return dist, archive_path


def _plan(tmp_path, version: str, *, previous_manifest=None) -> PublishPlan:
    manifest = _manifest(version)
    dist, archive_path = _write_dist(tmp_path, manifest)
    return PublishPlan(
        manifest=manifest,
        dist=dist,
        archive_path=archive_path,
        previous_manifest=previous_manifest,
    )


def _seed_prior_release(backend: FakeBackend, version: str) -> Manifest:
    """Populate the backend as though ``version`` was already published."""

    contents = (
        ("xray/geoip.dat", b"prior-geoip"),
        ("sing-box/lite/example.json", b"prior-singbox"),
    )
    checksums = {
        relative: hashlib.sha256(content).hexdigest()
        for relative, content in contents
    }
    manifest = replace(
        _manifest(version, checksums=checksums),
        artifact_sizes={relative: len(content) for relative, content in contents},
    )
    for relative, content in contents:
        backend.put_object(
            f"releases/{version}/{relative}",
            content,
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )
        backend.put_object(
            f"latest/{relative}",
            content,
            content_type="application/octet-stream",
            cache_control="public, max-age=300, must-revalidate",
        )
    backend.put_object(
        "manifest.json",
        json.dumps({**manifest.to_json_dict(), "latest_version": version}).encode(
            "utf-8"
        ),
        content_type="application/json",
        cache_control="public, max-age=300, must-revalidate",
    )
    return manifest


# --- Happy path -------------------------------------------------------


def test_publish_release_uploads_immutable_release_tree(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0000-aaaaaaaa")

    publish_release(plan, backend)

    for relative in plan.manifest.checksums:
        key = f"releases/{plan.manifest.release_version}/{relative}"
        assert backend.get_object(key) == (plan.dist / relative).read_bytes()
        obj = backend.objects[key]
        assert obj.cache_control == "public, max-age=31536000, immutable"


def test_publish_release_copies_latest_from_verified_tree(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0001-bbbbbbbb")

    publish_release(plan, backend)

    for relative in plan.manifest.checksums:
        key = f"latest/{relative}"
        assert backend.get_object(key) == (plan.dist / relative).read_bytes()
        obj = backend.objects[key]
        assert obj.cache_control == "public, max-age=300, must-revalidate"


def test_publish_release_writes_manifest_pointer_last(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0002-cccccccc")

    publish_release(plan, backend)

    manifest_bytes = backend.get_object("manifest.json")
    payload = json.loads(manifest_bytes)
    assert payload["latest_version"] == "2026.08.26.0002-cccccccc"

    sums_bytes = backend.get_object("SHA256SUMS").decode("utf-8")
    for relative, digest in plan.manifest.checksums.items():
        assert f"{digest}  {relative}" in sums_bytes


def test_publish_release_order_is_releases_then_latest_then_manifest(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0003-dddddddd")

    publish_release(plan, backend)

    keys = [entry[1] for entry in backend.put_log]
    releases_index = min(
        i for i, key in enumerate(keys) if key.startswith("releases/")
    )
    latest_index = min(i for i, key in enumerate(keys) if key.startswith("latest/"))
    manifest_index = keys.index("manifest.json")

    assert releases_index < latest_index < manifest_index


def test_publish_release_writes_sha256sums_before_manifest(tmp_path):
    # manifest.json must be the true last write of the whole sequence: with
    # SHA256SUMS written first, manifest.json's successful PUT is the
    # atomic pointer-flip moment with nothing else left that can fail.
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0009-44444445")

    publish_release(plan, backend)

    keys = [entry[1] for entry in backend.put_log]
    sums_index = keys.index("SHA256SUMS")
    manifest_index = keys.index("manifest.json")
    assert sums_index < manifest_index
    assert keys[-1] == "manifest.json"


def test_publish_release_purges_cache_for_latest_and_manifest(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0004-eeeeeeee")

    publish_release(plan, backend)

    assert backend.purged
    purged_paths = backend.purged[-1]
    assert "/manifest.json" in purged_paths
    assert any(path.startswith("/latest/") for path in purged_paths)


def test_publish_release_purge_happens_after_manifest_write(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0005-ffffffff")

    publish_release(plan, backend)

    manifest_put_tick = max(
        tick for tick, key in backend.put_log if key == "manifest.json"
    )
    assert backend.purge_index > manifest_put_tick


def test_publish_release_creates_draft_before_r2_upload(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0006-11111111")

    publish_release(plan, backend)

    assert backend.draft_created_index is not None
    first_r2_put_tick = min(
        tick for tick, key in backend.put_log if key.startswith("releases/")
    )
    assert backend.draft_created_index < first_r2_put_tick


def test_publish_release_finalizes_draft_after_manifest_pointer_verified(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0007-22222222")

    publish_release(plan, backend)

    assert backend.finalized_release_id == backend.created_release_id
    manifest_put_tick = max(
        tick for tick, key in backend.put_log if key == "manifest.json"
    )
    assert backend.finalize_index > manifest_put_tick


def test_publish_release_returns_release_version(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0008-33333333")

    result = publish_release(plan, backend)

    assert result == "2026.08.26.0008-33333333"


def test_publish_release_writes_complete_immutable_release_manifest(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0009-44444444")

    publish_release(plan, backend)

    key = f"releases/{plan.manifest.release_version}/manifest.json"
    assert json.loads(backend.get_object(key)) == plan.manifest.to_json_dict()
    assert backend.objects[key].cache_control == "public, max-age=31536000, immutable"


# --- Failure/cleanup: release-tree upload -----------------------------


def test_release_upload_failure_deletes_draft_and_release_tree(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0100-44444444")
    backend.fail_put_key = "releases/2026.08.26.0100-44444444/xray/geoip.dat"

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    assert backend.deleted_release_id == backend.created_release_id
    assert not backend.finalized_release_id
    assert backend.deleted_prefixes == [
        "releases/2026.08.26.0100-44444444/"
    ]
    assert "manifest.json" not in backend.objects


def test_release_upload_failure_does_not_touch_latest_or_manifest(tmp_path):
    backend = FakeBackend()
    prior = _seed_prior_release(backend, "2026.08.25.0000-00000000")
    plan = _plan(tmp_path, "2026.08.26.0101-55555555", previous_manifest=prior)
    backend.fail_put_key = (
        "releases/2026.08.26.0101-55555555/sing-box/lite/example.json"
    )

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.25.0000-00000000"
    assert backend.get_object("latest/xray/geoip.dat") == b"prior-geoip"


# --- Failure/cleanup: read-back verification ---------------------------


def test_readback_verification_failure_triggers_cleanup(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0200-66666666")
    backend.corrupt_readback_key = (
        "releases/2026.08.26.0200-66666666/xray/geoip.dat"
    )

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    assert backend.deleted_release_id == backend.created_release_id
    assert backend.deleted_prefixes == ["releases/2026.08.26.0200-66666666/"]
    assert "manifest.json" not in backend.objects
    assert not any(key.startswith("latest/") for key in backend.objects)


# --- Failure/cleanup: /latest/* upload partway through multiple objects ---


def test_latest_upload_partial_failure_restores_prior_latest_tree(tmp_path):
    backend = FakeBackend()
    prior = _seed_prior_release(backend, "2026.08.25.0001-00000001")
    plan = _plan(tmp_path, "2026.08.26.0300-77777777", previous_manifest=prior)
    # First latest/* object succeeds, second fails -- a genuine partial
    # overwrite that cleanup must repair.
    backend.fail_put_key = "latest/sing-box/lite/example.json"

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    # The release tree itself is cleaned up too.
    assert backend.deleted_release_id == backend.created_release_id
    assert backend.deleted_prefixes == ["releases/2026.08.26.0300-77777777/"]

    # /latest/* is fully restored to the prior version's bytes, including
    # the object that succeeded in the failed attempt.
    assert backend.get_object("latest/xray/geoip.dat") == b"prior-geoip"
    assert backend.get_object("latest/sing-box/lite/example.json") == b"prior-singbox"

    # The manifest pointer never moved.
    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.25.0001-00000001"


def test_latest_upload_failure_without_prior_manifest_still_cleans_up_release(
    tmp_path,
):
    # Initial release (no previous_manifest): there is nothing to restore
    # /latest/* to, but the release tree and draft must still be cleaned up.
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0301-88888888", previous_manifest=None)
    backend.fail_put_key = "latest/xray/geoip.dat"

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    assert backend.deleted_release_id == backend.created_release_id
    assert backend.deleted_prefixes == ["releases/2026.08.26.0301-88888888/"]
    assert "manifest.json" not in backend.objects


# --- Failure/cleanup: manifest write ------------------------------------


def test_manifest_write_failure_triggers_cleanup_and_latest_restoration(tmp_path):
    backend = FakeBackend()
    prior = _seed_prior_release(backend, "2026.08.25.0002-00000002")
    plan = _plan(tmp_path, "2026.08.26.0400-99999999", previous_manifest=prior)
    backend.fail_put_key = "manifest.json"

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    assert backend.deleted_release_id == backend.created_release_id
    assert backend.deleted_prefixes == ["releases/2026.08.26.0400-99999999/"]

    assert backend.get_object("latest/xray/geoip.dat") == b"prior-geoip"
    assert backend.get_object("latest/sing-box/lite/example.json") == b"prior-singbox"

    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.25.0002-00000002"


def test_sha256sums_failure_leaves_manifest_pointer_at_prior_version(tmp_path):
    # Regression test for the exact interleaving a spec-compliance review
    # found unsafe under the old (pre-fix) write order, where manifest.json
    # was uploaded BEFORE SHA256SUMS: if SHA256SUMS's PUT then failed, the
    # exception unwound into cleanup, which deleted the release tree
    # manifest.json now pointed at and restored /latest/*, but never
    # touched manifest.json itself -- leaving the root pointer naming a
    # version whose tree had just been deleted. With SHA256SUMS now written
    # first and manifest.json strictly last, a SHA256SUMS failure happens
    # entirely before the pointer write is even attempted, so cleanup must
    # leave the pointer at the PRIOR version, exactly like every other
    # failure before the manifest write.
    backend = FakeBackend()
    prior = _seed_prior_release(backend, "2026.08.25.0004-00000004")
    plan = _plan(tmp_path, "2026.08.26.0410-99999998", previous_manifest=prior)
    backend.fail_put_key = "SHA256SUMS"

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    # The root pointer is exactly what it was before this publication
    # attempt began -- manifest.json's PUT was never reached by this failed
    # run, since SHA256SUMS is written strictly before it.
    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.25.0004-00000004"

    assert backend.deleted_release_id == backend.created_release_id
    assert not backend.finalized_release_id
    assert backend.deleted_prefixes == ["releases/2026.08.26.0410-99999998/"]
    assert backend.get_object("latest/xray/geoip.dat") == b"prior-geoip"
    assert backend.get_object("latest/sing-box/lite/example.json") == b"prior-singbox"


# --- Failure/cleanup: cache purge ---------------------------------------


def test_purge_failure_does_not_roll_back_manifest_pointer(tmp_path):
    # Per the design doc, purge is step 4, after the atomic pointer flip
    # (step 3) already succeeded. A purge failure must NOT undo the
    # manifest write or delete the release/draft -- the release is already
    # live; only the CDN cache may be stale until purge is retried.
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0500-aaaaaaab")
    backend.fail_purge = True

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.26.0500-aaaaaaab"
    assert backend.deleted_release_id is None
    assert backend.finalized_release_id == backend.created_release_id


# --- Failure: GitHub Release finalization after R2 already published ----


def test_finalize_failure_after_r2_publication_leaves_r2_state_intact(tmp_path):
    # If R2 publication (steps 1-3) has already succeeded when finalization
    # fails, R2 is already live and correctly serving the new version.
    # publish_release must raise PublishError but must NOT roll back R2
    # state, and must NOT delete the draft release -- deleting it would
    # orphan the already-correct R2 state with no discoverable GitHub
    # Release at all. See the design doc's "Publication and CDN" section:
    # it only prescribes deleting the draft when R2 publication itself
    # fails (before the pointer flip); it is silent on a later finalization
    # failure, so this test documents the chosen interpretation.
    backend = FakeBackend()
    prior = _seed_prior_release(backend, "2026.08.25.0005-00000005")
    plan = _plan(tmp_path, "2026.08.26.0420-99999997", previous_manifest=prior)
    backend.fail_finalize = True

    with pytest.raises(PublishError, match="finalization failed"):
        publish_release(plan, backend)

    # R2 state (manifest pointer, /latest/*, /releases/<version>/) is left
    # exactly as the successful publication produced it -- not rolled back.
    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.26.0420-99999997"
    assert backend.get_object("latest/xray/geoip.dat") == _content_for(
        "2026.08.26.0420-99999997", "xray/geoip.dat"
    )
    for relative in plan.manifest.checksums:
        key = f"releases/2026.08.26.0420-99999997/{relative}"
        assert key in backend.objects

    # The draft release is left untouched -- not deleted, not finalized.
    assert backend.created_release_id is not None
    assert backend.deleted_release_id is None
    assert backend.finalized_release_id is None


# --- Cleanup failure reporting -------------------------------------------


def test_cleanup_failure_is_reported_and_never_touches_manifest(tmp_path):
    backend = FakeBackend()
    prior = _seed_prior_release(backend, "2026.08.25.0003-00000003")
    plan = _plan(tmp_path, "2026.08.26.0600-bbbbbbbc", previous_manifest=prior)
    backend.fail_put_key = "manifest.json"
    backend.fail_delete_prefix = True

    with pytest.raises(PublishError) as excinfo:
        publish_release(plan, backend)

    assert "cleanup" in str(excinfo.value).lower()
    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.25.0003-00000003"
    assert backend.finalized_release_id != backend.created_release_id


def test_no_credentials_leak_into_publish_error_messages(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0700-cccccccd")
    backend.fail_put_key = "releases/2026.08.26.0700-cccccccd/xray/geoip.dat"
    backend.secret_marker = "SUPER-SECRET-R2-KEY"

    with pytest.raises(PublishError) as excinfo:
        publish_release(plan, backend)

    assert "SUPER-SECRET-R2-KEY" not in str(excinfo.value)


# --- Rollback -------------------------------------------------------------


def test_rollback_copies_prior_release_tree_into_latest(tmp_path):
    backend = FakeBackend()
    _seed_prior_release(backend, "2026.08.20.0000-old00000")
    target = _manifest("2026.08.19.0000-older0000")
    for relative in target.checksums:
        content = _content_for(target.release_version, relative)
        backend.put_object(
            f"releases/2026.08.19.0000-older0000/{relative}",
            content,
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )

    rollback(
        "2026.08.19.0000-older0000", backend, target_manifest=target
    )

    assert backend.get_object("latest/xray/geoip.dat") == _content_for(
        target.release_version, "xray/geoip.dat"
    )
    assert backend.get_object(
        "latest/sing-box/lite/example.json"
    ) == _content_for(target.release_version, "sing-box/lite/example.json")
    manifest_payload = json.loads(backend.get_object("manifest.json"))
    assert manifest_payload["latest_version"] == "2026.08.19.0000-older0000"


def test_rollback_writes_manifest_after_latest_copy():
    backend = FakeBackend()
    _seed_prior_release(backend, "2026.08.20.0000-old00000")
    target = _manifest("2026.08.19.0000-older0000")
    for relative in target.checksums:
        content = _content_for(target.release_version, relative)
        backend.put_object(
            f"releases/2026.08.19.0000-older0000/{relative}",
            content,
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )

    rollback(
        "2026.08.19.0000-older0000", backend, target_manifest=target
    )

    keys = [entry[1] for entry in backend.put_log]
    latest_index = min(i for i, key in enumerate(keys) if key.startswith("latest/"))
    manifest_index = max(i for i, key in enumerate(keys) if key == "manifest.json")
    assert latest_index < manifest_index


def test_rollback_never_rebuilds_release_only_copies_and_points(tmp_path):
    # Rollback must not touch releases/* at all -- it only reads the prior
    # immutable tree and writes latest/* + manifest.json.
    backend = FakeBackend()
    target = _manifest("2026.08.19.0000-older0000")
    for relative in target.checksums:
        content = _content_for(target.release_version, relative)
        backend.put_object(
            f"releases/2026.08.19.0000-older0000/{relative}",
            content,
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )
    before_release_puts = [
        entry for entry in backend.put_log if entry[1].startswith("releases/")
    ]

    rollback(
        "2026.08.19.0000-older0000", backend, target_manifest=target
    )

    after_release_puts = [
        entry for entry in backend.put_log if entry[1].startswith("releases/")
    ]
    assert before_release_puts == after_release_puts


def test_rollback_installs_complete_target_root_state_and_purges_paths():
    backend = FakeBackend()
    current = replace(
        _manifest("2026.08.20.0000-current0"),
        content_fingerprint="1" * 64,
        policy_fingerprint="2" * 64,
        category_counts={"lite:current": 9},
        tool_versions={"xray": "current"},
    )
    target = replace(
        _manifest("2026.08.19.0000-target00"),
        content_fingerprint="a" * 64,
        policy_fingerprint="b" * 64,
        category_counts={"lite:target": 3},
        tool_versions={"xray": "target"},
    )
    backend.put_object(
        "manifest.json",
        json.dumps(
            {**current.to_json_dict(), "latest_version": current.release_version}
        ).encode(),
        content_type="application/json",
        cache_control="public, max-age=300, must-revalidate",
    )
    backend.put_object(
        "SHA256SUMS",
        b"current checksums\n",
        content_type="text/plain",
        cache_control="public, max-age=300, must-revalidate",
    )
    for relative in target.checksums:
        backend.put_object(
            f"releases/{target.release_version}/{relative}",
            _content_for(target.release_version, relative),
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )

    rollback(target.release_version, backend, target_manifest=target)

    expected_root = {**target.to_json_dict(), "latest_version": target.release_version}
    assert json.loads(backend.get_object("manifest.json")) == expected_root
    expected_sums = "".join(
        f"{digest}  {relative}\n"
        for relative, digest in sorted(target.checksums.items())
    ).encode()
    assert backend.get_object("SHA256SUMS") == expected_sums
    put_keys = [key for _, key in backend.put_log]
    latest_index = max(
        i for i, key in enumerate(put_keys) if key.startswith("latest/")
    )
    sums_index = max(i for i, key in enumerate(put_keys) if key == "SHA256SUMS")
    assert latest_index < sums_index
    assert sums_index < max(
        i for i, key in enumerate(put_keys) if key == "manifest.json"
    )
    assert backend.purged == [
        tuple(
            sorted(
                {"/manifest.json", "/SHA256SUMS"}
                | {f"/latest/{relative}" for relative in target.checksums}
            )
        )
    ]
    assert backend.purge_index > backend.put_log[-1][0]


def test_rollback_rejects_tampered_immutable_target_before_writing_latest():
    backend = FakeBackend()
    target = _manifest("2026.08.19.0000-target00")
    for relative in target.checksums:
        content = (
            b"tampered"
            if relative == "xray/geoip.dat"
            else _content_for(target.release_version, relative)
        )
        backend.put_object(
            f"releases/{target.release_version}/{relative}",
            content,
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )
    before = len(backend.put_log)

    with pytest.raises(PublishError, match=r"xray/geoip.dat.*checksum"):
        rollback(target.release_version, backend, target_manifest=target)

    assert not any(
        key.startswith("latest/") for _, key in backend.put_log[before:]
    )
    assert "manifest.json" not in backend.objects


def test_rollback_verifies_each_latest_copy_before_writing_root_metadata():
    backend = FakeBackend()
    target = _manifest("2026.08.19.0000-target00")
    for relative in target.checksums:
        backend.put_object(
            f"releases/{target.release_version}/{relative}",
            _content_for(target.release_version, relative),
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )
    backend.corrupt_readback_key = "latest/sing-box/lite/example.json"

    with pytest.raises(PublishError, match=r"read-back verification failed"):
        rollback(target.release_version, backend, target_manifest=target)

    assert "SHA256SUMS" not in backend.objects
    assert "manifest.json" not in backend.objects
    assert backend.purged == []


def test_rollback_rejects_inconsistent_target_sha256sums_before_copying():
    backend = FakeBackend()
    target = replace(
        _manifest("2026.08.19.0000-target00"),
        sha256sums_sha256="0" * 64,
    )

    with pytest.raises(PublishError, match=r"SHA256SUMS hash"):
        rollback(target.release_version, backend, target_manifest=target)

    assert backend.put_log == []
    assert backend.purged == []


def test_rollback_rejects_incomplete_archive_internal_manifest():
    backend = FakeBackend()
    target = replace(
        _manifest("2026.08.19.0000-target00"),
        archive_filename=None,
        archive_sha256=None,
        archive_size_bytes=None,
    )

    with pytest.raises(PublishError, match=r"archive_"):
        rollback(target.release_version, backend, target_manifest=target)

    assert backend.put_log == []
    assert backend.purged == []


def test_rollback_rejects_version_that_does_not_match_target_manifest():
    backend = FakeBackend()
    target = _manifest("2026.08.19.0000-target00")

    with pytest.raises(PublishError, match="does not match target manifest"):
        rollback("2026.08.18.0000-wrong000", backend, target_manifest=target)

    assert backend.put_log == []


def test_publish_backend_protocol_is_satisfied_by_fake_backend():
    assert isinstance(FakeBackend(), PublishBackend)


# --- Failure/cleanup: create_draft_release fails before any R2 write -----


def test_create_release_failure_raises_and_attempts_no_r2_writes(tmp_path):
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0800-dddddddd")
    backend.fail_create_release = True

    with pytest.raises(PublishError):
        publish_release(plan, backend)

    assert backend.put_log == []
    assert backend.created_release_id is None


def test_create_release_failure_cleanup_does_not_crash_on_missing_release_id(
    tmp_path,
):
    # release_id is None when create_draft_release itself is the failure --
    # _cleanup_failed_publication must skip delete_release entirely rather
    # than trying to delete a release that was never created.
    backend = FakeBackend()
    plan = _plan(tmp_path, "2026.08.26.0801-eeeeeeee")
    backend.fail_create_release = True

    with pytest.raises(PublishError) as excinfo:
        publish_release(plan, backend)

    assert backend.deleted_release_id is None
    # The release tree delete_prefix cleanup step still runs (no-op, since
    # nothing was ever uploaded) and must not itself raise or fail.
    assert backend.deleted_prefixes == ["releases/2026.08.26.0801-eeeeeeee/"]
    assert "cleaned up" in str(excinfo.value) or "cleanup" in str(excinfo.value).lower()


# --- Credential repr/str redaction ----------------------------------------


def test_r2_credentials_repr_redacts_secrets():
    creds = R2Credentials(
        account_id="acct-123",
        access_key_id="AKIA-SUPER-SECRET-ID",
        secret_access_key="SUPER-SECRET-KEY-VALUE",
        bucket="routing-bucket",
        endpoint_url="https://example.r2.cloudflarestorage.com",
    )

    text = repr(creds)

    assert "AKIA-SUPER-SECRET-ID" not in text
    assert "SUPER-SECRET-KEY-VALUE" not in text
    assert "routing-bucket" in text
    assert str(creds) == text


def test_cloudflare_credentials_repr_redacts_secrets():
    creds = CloudflareCredentials(
        zone_id="zone-123", api_token="CF-SUPER-SECRET-TOKEN"
    )

    text = repr(creds)

    assert "CF-SUPER-SECRET-TOKEN" not in text
    assert "zone-123" in text
    assert str(creds) == text


# --- CliBackend.delete_prefix pagination ----------------------------------


class _FakeAwsProcess:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes = b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _make_cli_backend(aws_subprocess_runner, tmp_path):
    return CliBackend(
        r2=R2Credentials(
            account_id="acct",
            access_key_id="key",
            secret_access_key="secret",
            bucket="bucket",
            endpoint_url="https://example.r2.cloudflarestorage.com",
        ),
        cloudflare=CloudflareCredentials(zone_id="zone", api_token="token"),
        repo="owner/repo",
        workdir=tmp_path,
        aws_subprocess_runner=aws_subprocess_runner,
    )


def test_cli_backend_delete_prefix_paginates_across_multiple_pages(tmp_path):
    # Two pages: first truncated with a continuation token, second final.
    page_one = json.dumps(
        {
            "Contents": [{"Key": f"releases/v1/file-{i}.bin"} for i in range(3)],
            "IsTruncated": True,
            "NextContinuationToken": "token-abc",
        }
    ).encode("utf-8")
    page_two = json.dumps(
        {
            "Contents": [{"Key": f"releases/v1/file-{i}.bin"} for i in range(3, 5)],
            "IsTruncated": False,
        }
    ).encode("utf-8")

    calls: list[list[str]] = []

    def fake_runner(command, **kwargs):
        calls.append(list(command))
        if "list-objects-v2" in command:
            if "--continuation-token" in command:
                assert command[command.index("--continuation-token") + 1] == (
                    "token-abc"
                )
                return _FakeAwsProcess(0, page_two)
            return _FakeAwsProcess(0, page_one)
        assert "delete-object" in command
        return _FakeAwsProcess(0, b"")

    backend = _make_cli_backend(fake_runner, tmp_path)
    backend.delete_prefix("releases/v1/")

    list_calls = [c for c in calls if "list-objects-v2" in c]
    delete_calls = [c for c in calls if "delete-object" in c]

    # Exactly two list-objects-v2 calls (one per page), and the pagination
    # loop collected every key across both pages before deleting anything.
    assert len(list_calls) == 2
    assert len(delete_calls) == 5
    deleted_keys = {c[c.index("--key") + 1] for c in delete_calls}
    assert deleted_keys == {f"releases/v1/file-{i}.bin" for i in range(5)}

    # Every list-objects-v2 call pins --output json.
    for call in list_calls:
        assert "--output" in call
        assert call[call.index("--output") + 1] == "json"


def test_cli_backend_delete_prefix_single_page_no_pagination(tmp_path):
    page = json.dumps(
        {
            "Contents": [{"Key": "releases/v1/only.bin"}],
            "IsTruncated": False,
        }
    ).encode("utf-8")

    calls: list[list[str]] = []

    def fake_runner(command, **kwargs):
        calls.append(list(command))
        if "list-objects-v2" in command:
            return _FakeAwsProcess(0, page)
        return _FakeAwsProcess(0, b"")

    backend = _make_cli_backend(fake_runner, tmp_path)
    backend.delete_prefix("releases/v1/")

    list_calls = [c for c in calls if "list-objects-v2" in c]
    assert len(list_calls) == 1
    assert "--continuation-token" not in list_calls[0]


def test_cli_backend_delete_prefix_empty_listing_deletes_nothing(tmp_path):
    page = json.dumps({"IsTruncated": False}).encode("utf-8")

    calls: list[list[str]] = []

    def fake_runner(command, **kwargs):
        calls.append(list(command))
        return _FakeAwsProcess(0, page)

    backend = _make_cli_backend(fake_runner, tmp_path)
    backend.delete_prefix("releases/v1/")

    assert all("delete-object" not in c for c in calls)
