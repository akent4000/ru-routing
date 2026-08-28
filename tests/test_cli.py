import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from ru_routing.cli import (
    _handle_publish,
    _handle_rollback,
    build_parser,
    main,
)
from ru_routing.package import Manifest
from ru_routing.publish import FakeBackend

_RELATIVE_PATHS = ("xray/geoip.dat", "sing-box/lite/example.json")


def test_cli_exposes_pipeline_commands(capsys):
    assert main(["--help"]) == 0

    output = capsys.readouterr().out
    commands = ["fetch", "build", "check", "release-decision", "publish", "rollback"]
    assert all(command in output for command in commands)


@pytest.mark.parametrize(
    ("command", "extra_args"),
    [
        ("fetch", []),
        ("build", ["--dist", "/tmp/unused-dist"]),
        ("check", []),
    ],
)
def test_commands_requiring_a_source_report_a_clear_usage_error(
    command, extra_args, capsys
):
    """fetch/build/check are wired -- they now fail on missing required
    arguments (fetch needs --destination; build/check need --fixtures or
    --inputs) rather than the old blanket "not wired yet" stub message. See
    tests/test_pipeline.py for the full fixture-driven end-to-end coverage
    of these commands actually running the pipeline.
    """

    exit_code = main([command, *extra_args])

    assert exit_code == 2


def test_config_only_check_accepts_an_explicit_config_root_outside_the_repository(
    capsys, monkeypatch, tmp_path
):
    config_root = Path("config").resolve()
    monkeypatch.chdir(tmp_path)

    assert main(["check", "--config-only", "--config", str(config_root)]) == 0
    assert "configuration is valid" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# publish / rollback
# ---------------------------------------------------------------------------


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


def _write_dist(tmp_path: Path, manifest: Manifest) -> Path:
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
    (tmp_path / manifest.archive_filename).write_bytes(b"archive-bytes")
    return dist


def _write_manifest_file(path: Path, manifest: Manifest) -> Path:
    path.write_text(json.dumps(manifest.to_json_dict()), encoding="utf-8")
    return path


class _Namespace:
    """Minimal stand-in for argparse.Namespace built from keyword args."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def test_publish_parses_required_arguments():
    parser = build_parser()
    arguments = parser.parse_args(
        ["publish", "--dist", "/tmp/dist", "--repo", "owner/name"]
    )
    assert arguments.dist == Path("/tmp/dist")
    assert arguments.repo == "owner/name"
    assert arguments.previous_manifest is None


def test_rollback_parses_required_arguments():
    parser = build_parser()
    arguments = parser.parse_args(
        [
            "rollback",
            "--version",
            "2026.08.26.0000-aaaaaaaa",
            "--target-manifest",
            "/tmp/manifest.json",
            "--repo",
            "owner/name",
        ]
    )
    assert arguments.version == "2026.08.26.0000-aaaaaaaa"
    assert arguments.target_manifest == Path("/tmp/manifest.json")


def test_publish_missing_env_credentials_produces_clear_error_no_traceback(
    capsys, monkeypatch, tmp_path
):
    monkeypatch.delenv("R2_ACCOUNT_ID", raising=False)
    manifest = _manifest("2026.08.26.0000-aaaaaaaa")
    dist = _write_dist(tmp_path, manifest)
    arguments = _Namespace(dist=dist, previous_manifest=None, repo="owner/name")

    exit_code = _handle_publish(arguments)

    assert exit_code != 0
    error = capsys.readouterr().err
    assert "publish failed" in error
    assert "R2_ACCOUNT_ID" in error
    assert "Traceback" not in error


def test_publish_missing_repo_produces_clear_error(capsys, monkeypatch, tmp_path):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    manifest = _manifest("2026.08.26.0000-aaaaaaaa")
    dist = _write_dist(tmp_path, manifest)
    arguments = _Namespace(dist=dist, previous_manifest=None, repo=None)

    exit_code = _handle_publish(arguments)

    assert exit_code != 0
    error = capsys.readouterr().err
    assert "GITHUB_REPOSITORY" in error


def test_publish_missing_manifest_produces_clear_error(capsys, tmp_path):
    dist = tmp_path / "dist"
    dist.mkdir()
    arguments = _Namespace(dist=dist, previous_manifest=None, repo="owner/name")

    exit_code = _handle_publish(arguments)

    assert exit_code != 0
    error = capsys.readouterr().err
    assert "manifest.json" in error
    assert "Traceback" not in error


def test_publish_missing_archive_produces_clear_error(capsys, tmp_path):
    manifest = _manifest("2026.08.26.0000-aaaaaaaa")
    dist = _write_dist(tmp_path, manifest)
    (tmp_path / manifest.archive_filename).unlink()
    arguments = _Namespace(dist=dist, previous_manifest=None, repo="owner/name")

    exit_code = _handle_publish(arguments)

    assert exit_code != 0
    error = capsys.readouterr().err
    assert "archive" in error.lower()


def test_publish_succeeds_against_fake_backend(capsys, tmp_path):
    manifest = _manifest("2026.08.26.0000-aaaaaaaa")
    dist = _write_dist(tmp_path, manifest)
    arguments = _Namespace(dist=dist, previous_manifest=None, repo="owner/name")

    backend = FakeBackend()
    exit_code = _handle_publish(arguments, backend_factory=lambda repo: backend)

    assert exit_code == 0
    output = capsys.readouterr().out
    assert manifest.release_version in output
    assert backend.finalized_release_id == backend.created_release_id
    assert json.loads(backend.get_object("manifest.json"))["latest_version"] == (
        manifest.release_version
    )


def test_rollback_succeeds_against_fake_backend(capsys, tmp_path):
    prior_version = "2026.08.20.0000-bbbbbbbb"
    prior_manifest = _manifest(prior_version)
    backend = FakeBackend()
    for relative, digest in prior_manifest.checksums.items():
        content = _content_for(prior_version, relative)
        assert hashlib.sha256(content).hexdigest() == digest
        backend.put_object(
            f"releases/{prior_version}/{relative}",
            content,
            content_type="application/octet-stream",
            cache_control="public, max-age=31536000, immutable",
        )
    backend.put_object(
        "manifest.json",
        json.dumps(
            {**prior_manifest.to_json_dict(), "latest_version": "some-other-version"}
        ).encode("utf-8"),
        content_type="application/json",
        cache_control="public, max-age=300, must-revalidate",
    )

    target_manifest_path = _write_manifest_file(
        tmp_path / "target-manifest.json", prior_manifest
    )
    arguments = _Namespace(
        version=prior_version,
        target_manifest=target_manifest_path,
        repo="owner/name",
    )

    exit_code = _handle_rollback(arguments, backend_factory=lambda repo: backend)

    assert exit_code == 0
    output = capsys.readouterr().out
    assert prior_version in output
    assert json.loads(backend.get_object("manifest.json"))["latest_version"] == (
        prior_version
    )


def test_rollback_missing_target_manifest_produces_clear_error(capsys, tmp_path):
    arguments = _Namespace(
        version="2026.08.26.0000-aaaaaaaa",
        target_manifest=tmp_path / "missing.json",
        repo="owner/name",
    )

    exit_code = _handle_rollback(arguments)

    assert exit_code != 0
    error = capsys.readouterr().err
    assert "rollback failed" in error
    assert "Traceback" not in error


def test_rollback_rejects_cli_version_different_from_target_manifest(
    capsys, tmp_path
):
    target = _manifest("2026.08.20.0000-bbbbbbbb")
    target_path = _write_manifest_file(tmp_path / "target.json", target)
    arguments = _Namespace(
        version="2026.08.19.0000-aaaaaaaa",
        target_manifest=target_path,
        repo="owner/name",
    )
    backend = FakeBackend()

    exit_code = _handle_rollback(
        arguments, backend_factory=lambda repo: backend
    )

    assert exit_code != 0
    assert "does not match target manifest" in capsys.readouterr().err


def test_rollback_rejects_archive_internal_manifest_with_clear_error(
    capsys, tmp_path
):
    backend = FakeBackend()
    target = replace(
        _manifest("2026.08.26.0000-aaaaaaaa"),
        archive_filename=None,
        archive_sha256=None,
        archive_size_bytes=None,
    )
    target_path = _write_manifest_file(tmp_path / "target.json", target)
    arguments = _Namespace(
        version=target.release_version,
        target_manifest=target_path,
        repo="owner/name",
    )

    exit_code = _handle_rollback(
        arguments, backend_factory=lambda repo: backend
    )

    assert exit_code == 4
    error = capsys.readouterr().err
    assert "rollback failed" in error
    assert "archive_" in error
    assert backend.put_log == []
    assert backend.put_log == []
