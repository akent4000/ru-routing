"""End-to-end CLI orchestration tests, driven entirely from committed fixtures.

These tests exercise ``ru_routing.cli.main`` the way a real invocation would
(argv in, exit code + dist tree out) but replace every native-tool boundary
(sing-box/mihomo/xray/dlc/geoip binaries, and the Go RE2 regex validator)
with in-process fakes, and replace live upstream HTTP fetch with the
committed ``tests/fixtures/upstreams/registry`` tree -- see
``tests/test_examples.py``'s ``_FixtureGeodataReader``/fixture-source
pattern, which this reuses via the CLI surface instead of calling the
pipeline stage functions directly. No network access and no real
dlc/geoip/sing-box/mihomo/xray/go binaries are required to run this file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ru_routing.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "upstreams" / "registry"
CONFIG_DIR = REPO_ROOT / "config"
UNVERIFIED_LICENSE_SOURCES = {
    "hydraponique/roscomvpn-geoip",
    "itdoginfo/allow-domains",
}


def _run(args, monkeypatch=None):
    return main(args)


def test_build_fixtures_produces_the_complete_output_contract(tmp_path):
    dist = tmp_path / "dist"

    exit_code = main(
        [
            "build",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
        ]
    )

    assert exit_code == 0

    # --- Output Contract: dist/ tree (design doc "Output Contract") ---
    assert (dist / "xray" / "geoip-lite.dat").is_file()
    assert (dist / "xray" / "geosite-lite.dat").is_file()
    assert (dist / "xray" / "geoip.dat").is_file()
    assert (dist / "xray" / "geosite.dat").is_file()

    assert any((dist / "sing-box" / "lite").glob("*.json"))
    assert any((dist / "sing-box" / "lite").glob("*.srs"))
    assert any((dist / "sing-box" / "server").glob("*.json"))
    assert any((dist / "sing-box" / "server").glob("*.srs"))

    assert any((dist / "mihomo" / "lite").glob("*.yaml"))
    assert any((dist / "mihomo" / "lite").glob("*.mrs"))
    assert any((dist / "mihomo" / "server").glob("*.yaml"))
    assert any((dist / "mihomo" / "server").glob("*.mrs"))

    assert any((dist / "raw" / "lite" / "domains").glob("*.txt"))
    assert any((dist / "raw" / "server" / "domains").glob("*.txt"))

    assert (dist / "examples" / "xray" / "lite.json").is_file()
    assert (dist / "examples" / "xray" / "server.json").is_file()
    assert (dist / "examples" / "sing-box" / "lite.json").is_file()
    assert (dist / "examples" / "sing-box" / "server.json").is_file()
    assert (dist / "examples" / "mihomo" / "lite.yaml").is_file()
    assert (dist / "examples" / "mihomo" / "server.yaml").is_file()

    assert (dist / "manifest.json").is_file()
    assert (dist / "SHA256SUMS").is_file()

    manifest = json.loads((dist / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["content_fingerprint"]
    assert manifest["policy_fingerprint"]
    assert manifest["release_version"]
    assert manifest["sources"]
    assert manifest["category_counts"]
    assert UNVERIFIED_LICENSE_SOURCES.isdisjoint(
        source["name"] for source in manifest["sources"]
    )

    # Examples embed the computed release version, not the raw token.
    example_text = (dist / "examples" / "xray" / "lite.json").read_text(
        encoding="utf-8"
    )
    assert "{{VERSION}}" not in example_text
    assert manifest["release_version"] in example_text


def test_build_fixtures_is_deterministic_across_two_runs(tmp_path):
    dist_a = tmp_path / "dist-a"
    dist_b = tmp_path / "dist-b"

    for dist in (dist_a, dist_b):
        exit_code = main(
            [
                "build",
                "--fixtures",
                str(FIXTURES_DIR),
                "--dist",
                str(dist),
                "--config",
                str(CONFIG_DIR),
                "--fake-native-tools",
                "--built-at",
                "2026-01-01T00:00:00+00:00",
            ]
        )
        assert exit_code == 0

    checksums_a = (dist_a / "SHA256SUMS").read_text(encoding="utf-8")
    checksums_b = (dist_b / "SHA256SUMS").read_text(encoding="utf-8")
    assert checksums_a == checksums_b

    manifest_a = json.loads((dist_a / "manifest.json").read_text(encoding="utf-8"))
    manifest_b = json.loads((dist_b / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_a["content_fingerprint"] == manifest_b["content_fingerprint"]
    assert manifest_a["policy_fingerprint"] == manifest_b["policy_fingerprint"]


def test_build_fixtures_is_deterministic_across_separate_python_processes(tmp_path):
    """Regression test for a real bug found during Task 10's Docker
    verification: the CLI's _FixtureGeodataReader originally derived its
    synthetic entry index from Python's built-in ``hash()``, which is
    salted per-process by PYTHONHASHSEED (random by default). Two builds in
    the *same* interpreter (see the sibling test above) could not catch
    this -- ``hash()`` is stable within one process -- but two separate
    ``docker compose run`` invocations produced completely different
    output. This test forces two different explicit hash seeds across two
    subprocesses to catch any reintroduction of that class of bug.
    """

    import os
    import subprocess
    import sys

    dist_a = tmp_path / "dist-a"
    dist_b = tmp_path / "dist-b"

    for dist, seed in ((dist_a, "1"), (dist_b, "2")):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(REPO_ROOT / "src"))
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "ru_routing.cli",
                "build",
                "--fixtures",
                str(FIXTURES_DIR),
                "--dist",
                str(dist),
                "--config",
                str(CONFIG_DIR),
                "--fake-native-tools",
                "--built-at",
                "2026-01-01T00:00:00+00:00",
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, result.stderr

    checksums_a = (dist_a / "SHA256SUMS").read_text(encoding="utf-8")
    checksums_b = (dist_b / "SHA256SUMS").read_text(encoding="utf-8")
    assert checksums_a == checksums_b


def test_check_runs_the_fixture_build_and_validation_without_publishing(tmp_path):
    dist = tmp_path / "dist"

    exit_code = main(
        [
            "check",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
        ]
    )

    assert exit_code == 0
    assert (dist / "manifest.json").is_file()


def test_release_decision_reports_initial_release_with_no_previous_manifest(
    tmp_path, capsys
):
    exit_code = main(
        [
            "release-decision",
            "--fixtures",
            str(FIXTURES_DIR),
            "--config",
            str(CONFIG_DIR),
        ]
    )

    assert exit_code == 0
    output = json.loads(capsys.readouterr().out)
    assert output["should_release"] is True
    assert output["reason"] == "initial release"
    assert output["version"]
    assert output["content_fingerprint"]
    assert output["policy_fingerprint"]


def test_release_decision_reports_no_change_against_a_matching_previous_manifest(
    tmp_path, capsys
):
    # First, compute the real fingerprints for this fixture set so the
    # "previous manifest" we hand back genuinely matches -- otherwise this
    # would only prove the "always different" path, not "no change".
    exit_code = main(
        [
            "release-decision",
            "--fixtures",
            str(FIXTURES_DIR),
            "--config",
            str(CONFIG_DIR),
        ]
    )
    assert exit_code == 0
    first = json.loads(capsys.readouterr().out)

    previous_manifest = tmp_path / "previous-manifest.json"
    previous_manifest.write_text(
        json.dumps(
            {
                "content_fingerprint": first["content_fingerprint"],
                "policy_fingerprint": first["policy_fingerprint"],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "release-decision",
            "--fixtures",
            str(FIXTURES_DIR),
            "--config",
            str(CONFIG_DIR),
            "--previous-manifest",
            str(previous_manifest),
        ]
    )

    assert exit_code == 0
    second = json.loads(capsys.readouterr().out)
    assert second["should_release"] is False
    assert second["reason"] == "no change"
    assert second["version"] is None


@pytest.mark.parametrize(
    ("command", "usage_fragment"),
    [("publish", "--dist"), ("rollback", "--version")],
)
def test_publish_and_rollback_require_their_arguments(command, usage_fragment, capsys):
    """publish/rollback are wired to the real Task 11 publish.py behavior
    (see tests/test_cli.py for full coverage against a FakeBackend); here we
    only confirm the CLI still fails argparse's required-argument check when
    invoked bare, rather than the old "not yet implemented" stub message.
    """

    exit_code = main([command])

    assert exit_code == 2
    error = capsys.readouterr().err
    assert usage_fragment in error


def test_build_requires_either_fixtures_or_inputs(capsys, tmp_path):
    exit_code = main(["build", "--dist", str(tmp_path / "dist")])

    assert exit_code == 2
    assert "--fixtures" in capsys.readouterr().err


def test_build_failure_in_a_late_stage_leaves_a_first_dist_absent(
    monkeypatch, capsys, tmp_path
):
    """Regression test: CLI-level orchestration must be atomic end-to-end.

    Each individual stage (generate_all, render_examples) already publishes
    atomically on its own, but before this fix ``_run_build`` ran every
    stage directly against the caller's real ``--dist``, so a failure in a
    later stage (here, package_build) after generate_all had already
    succeeded left ``--dist`` populated with a generate-only partial tree
    (no manifest.json, no SHA256SUMS) despite the nonzero exit code. With
    the outer staging/atomic-replace wrapper, a first build that fails late
    must leave ``--dist`` entirely absent.
    """

    import ru_routing.cli as cli_module

    def _boom(dist, metadata):
        raise cli_module.PackagingError("forced failure for atomicity test")

    monkeypatch.setattr(cli_module, "package_build", _boom)

    dist = tmp_path / "dist"
    exit_code = main(
        [
            "build",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
        ]
    )

    assert exit_code == 1
    assert "forced failure for atomicity test" in capsys.readouterr().err
    assert not dist.exists()
    # No stray staging/backup siblings left behind either.
    assert sorted(p.name for p in tmp_path.iterdir()) == []


def test_build_failure_in_a_late_stage_leaves_a_prior_dist_unchanged(
    monkeypatch, capsys, tmp_path
):
    """Same as above, but for a *subsequent* build over a previously
    complete ``--dist``: a late failure must leave the prior complete tree
    completely unchanged, not overwritten with a partial one.
    """

    import ru_routing.cli as cli_module

    dist = tmp_path / "dist"

    # First, a real successful build establishes a prior complete state.
    exit_code = main(
        [
            "build",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
            "--built-at",
            "2026-01-01T00:00:00+00:00",
        ]
    )
    assert exit_code == 0
    prior_manifest = (dist / "manifest.json").read_text(encoding="utf-8")
    prior_checksums = (dist / "SHA256SUMS").read_text(encoding="utf-8")

    def _boom(dist, metadata):
        raise cli_module.PackagingError("forced failure for atomicity test")

    monkeypatch.setattr(cli_module, "package_build", _boom)

    exit_code = main(
        [
            "build",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
            "--built-at",
            "2026-01-02T00:00:00+00:00",
        ]
    )

    assert exit_code == 1
    assert "forced failure for atomicity test" in capsys.readouterr().err
    assert dist.is_dir()
    assert (dist / "manifest.json").read_text(encoding="utf-8") == prior_manifest
    assert (dist / "SHA256SUMS").read_text(encoding="utf-8") == prior_checksums


def _force_publish_swap_to_fail(monkeypatch, cli_module):
    """Make ``_publish_dist``'s final ``os.replace(stage, destination)`` raise.

    Simulates a disk-full/cross-device/permission failure mid-swap, after
    every build stage (``_run_build_stages``) has already succeeded and
    written a complete tree to the outer staging directory. Wraps
    ``_publish_dist`` itself (rather than patching ``os.replace`` globally
    for the whole build) so the flakiness only arms once every stage has
    finished -- other stages (``generate``/``render``) do their own internal
    staged ``os.replace`` swaps that must keep succeeding normally.

    Only the swap-in call (``os.replace(stage, destination)``) is made to
    fail, identified by its exact (src, dst) pair rather than call order --
    on a first build that is the *only* ``os.replace`` call
    ``_publish_dist`` makes, while on a subsequent build (over a pre-existing
    ``destination``) it is the *second* call, after the ``destination ->
    backup`` swap-out. Either way, this leaves the earlier swap-out call (if
    any) and the recovery call (``os.replace(backup, destination)``) alone,
    so ``_publish_dist``'s own recovery branch still runs exactly as it does
    in production.
    """

    real_publish_dist = cli_module._publish_dist

    def _flaky_publish_dist(stage, destination):
        real_os_replace = cli_module.os.replace

        def _flaky_replace(src, dst):
            if src == stage and dst == destination:
                raise OSError("forced os.replace failure for publish-swap test")
            return real_os_replace(src, dst)

        with monkeypatch.context() as inner:
            inner.setattr(cli_module.os, "replace", _flaky_replace)
            real_publish_dist(stage, destination)

    monkeypatch.setattr(cli_module, "_publish_dist", _flaky_publish_dist)


def test_build_failure_in_publish_swap_leaves_no_orphaned_staging_dir_first(
    monkeypatch, tmp_path
):
    """Regression test: a failure inside ``_publish_dist`` itself (not just
    inside ``_run_build_stages``) must still clean up the outer staging
    directory ``_run_build`` created.

    Before this fix, ``_run_build``'s ``try/except`` only wrapped the
    ``_run_build_stages`` call, not the subsequent ``_publish_dist(stage,
    destination)`` call, so a failure in the atomic-swap step itself (e.g.
    the ``os.replace(stage, destination)`` swap-in failing) left the
    ``.{name}.tmp-*`` staging directory orphaned on disk forever, even
    though ``_publish_dist``'s own internal recovery logic correctly
    restored ``destination`` to its prior valid state.

    ``_publish_dist``'s own ``OSError`` is not currently caught/translated
    anywhere in the ``build``/``check`` CLI handlers (pre-existing,
    unrelated to this fix), so this drives ``_run_build`` directly rather
    than through ``main`` and asserts the ``OSError`` propagates.
    """

    import ru_routing.cli as cli_module

    parser = cli_module.build_parser()
    dist = tmp_path / "dist"
    arguments = parser.parse_args(
        [
            "build",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
        ]
    )

    _force_publish_swap_to_fail(monkeypatch, cli_module)

    with pytest.raises(OSError, match="forced os.replace failure"):
        cli_module._run_build(arguments, dist)

    # destination is correctly absent, matching its prior (never-existed) state.
    assert not dist.exists()
    # No orphaned `.dist.tmp-*` staging directory (or `.dist.previous` backup)
    # left behind in dist's parent. (A `<version>.tar.gz` sibling is expected
    # here -- package_build writes it as a deliberate sibling of `dist` during
    # the already-succeeded `_run_build_stages` step, before the publish swap
    # this test is exercising even runs; see package.py's docstring.)
    leftover_names = {p.name for p in tmp_path.iterdir()}
    assert not any(
        name.startswith(f".{dist.name}.tmp-") or name == f".{dist.name}.previous"
        for name in leftover_names
    ), leftover_names


def test_build_failure_in_publish_swap_leaves_no_orphaned_staging_dir_next(
    monkeypatch, tmp_path
):
    """Same as above, but for a *subsequent* build over a previously
    complete ``--dist``: the publish-swap failure must both restore
    ``destination`` to its prior complete state (``_publish_dist``'s own
    existing recovery guarantee) *and* leave no orphaned staging directory
    behind (the fix under test).
    """

    import ru_routing.cli as cli_module

    dist = tmp_path / "dist"

    # First, a real successful build establishes a prior complete state.
    exit_code = main(
        [
            "build",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
            "--built-at",
            "2026-01-01T00:00:00+00:00",
        ]
    )
    assert exit_code == 0
    prior_manifest = (dist / "manifest.json").read_text(encoding="utf-8")
    prior_checksums = (dist / "SHA256SUMS").read_text(encoding="utf-8")

    parser = cli_module.build_parser()
    arguments = parser.parse_args(
        [
            "build",
            "--fixtures",
            str(FIXTURES_DIR),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
            "--built-at",
            "2026-01-02T00:00:00+00:00",
        ]
    )

    _force_publish_swap_to_fail(monkeypatch, cli_module)

    with pytest.raises(OSError, match="forced os.replace failure"):
        cli_module._run_build(arguments, dist)

    # destination is restored to its prior complete state.
    assert dist.is_dir()
    assert (dist / "manifest.json").read_text(encoding="utf-8") == prior_manifest
    assert (dist / "SHA256SUMS").read_text(encoding="utf-8") == prior_checksums
    # No orphaned staging directory or leftover ".dist.previous" backup dir
    # left behind alongside the restored dist. (`<version>.tar.gz` siblings
    # are expected -- see the comment in the first-build variant above.)
    leftover_names = {p.name for p in tmp_path.iterdir()}
    assert not any(
        name.startswith(f".{dist.name}.tmp-") or name == f".{dist.name}.previous"
        for name in leftover_names
    ), leftover_names
    # No stray outer staging/backup siblings left behind (the first
    # successful build's release archive, a sibling of dist by design --
    # see package_build's docstring -- is expected and unrelated).
    leftovers = {
        p.name for p in tmp_path.iterdir() if p.name.startswith(".dist")
    }
    assert leftovers == set()


def test_build_inputs_reads_a_prior_fetch_output_directory_layout(tmp_path, capsys):
    """--inputs reads a directory shaped like fetch_all's own output: an
    objects/ dir of content-addressed blobs and a metadata/ dir of one JSON
    document per source (see fetch.py's _write_metadata), so `build --inputs`
    round-trips a real `fetch` command's output without ever touching the
    network itself. `fetch --offline-fixtures` (this test's own setup step)
    reproduces exactly that output tree offline, so this confirms the
    --inputs directory-layout contract independent of any live network call.
    """

    fetch_dest = tmp_path / "fetched"
    exit_code = main(
        [
            "fetch",
            "--config",
            str(CONFIG_DIR),
            "--destination",
            str(fetch_dest),
            "--offline-fixtures",
            str(FIXTURES_DIR),
        ]
    )
    assert exit_code == 0
    assert (fetch_dest / "metadata").is_dir()
    assert (fetch_dest / "objects").is_dir()

    # The registry declares geoip_dat/geosite_dat sources alongside
    # plain_text ones. No task through Task 9 implemented a real
    # GeodataReader (src/ru_routing/parsers.py's GeodataReader protocol has
    # no production implementation anywhere in this codebase), so `build
    # --inputs` cannot yet safely decode those binary sources -- it fails
    # loudly and clearly rather than silently reusing the fixture stand-in
    # (which would corrupt a real build). This is an honest, documented
    # limitation, not a --inputs wiring bug: --inputs does successfully
    # locate and read every declared source's fetched object(s) (see
    # `--inputs` directory-layout contract above) before hitting this wall.
    dist = tmp_path / "dist"
    exit_code = main(
        [
            "build",
            "--inputs",
            str(fetch_dest),
            "--dist",
            str(dist),
            "--config",
            str(CONFIG_DIR),
            "--fake-native-tools",
        ]
    )

    assert exit_code == 1
    assert "GeodataReader" in capsys.readouterr().err
