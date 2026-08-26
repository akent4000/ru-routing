"""Structural tests for the GitHub Actions workflows (Task 12).

These parse the actual YAML files under ``.github/workflows/`` and assert
the properties the design doc's "Change Detection and Versioning" and
"Validation and Failure Handling" sections require:

- ``ci.yml`` is fixture-only PR validation: no publish-capable permissions,
  no R2/Cloudflare/GitHub-release secrets referenced anywhere, and no live
  upstream fetch.
- ``update.yml`` is the hourly/manual live-publication workflow: exact cron
  ``17 * * * *``, ``workflow_dispatch``, a ``concurrency`` group, minimal
  ``contents: write``, and GitHub Actions environment protection.

YAML structure is parsed with ``yaml.safe_load`` wherever that is the
correct tool; a couple of assertions (e.g. "no secret ever appears in a
``run:`` step") are naturally substring/regex checks over the raw text
since that is what actually protects against an accidental credential
leak in a shell command.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CI_PATH = WORKFLOWS_DIR / "ci.yml"
UPDATE_PATH = WORKFLOWS_DIR / "update.yml"

# Secrets that must never be referenced in ci.yml (publish-capable /
# sensitive credentials only -- not the non-sensitive R2/Cloudflare
# "variables").
_PUBLISH_SECRETS = (
    "R2_ACCOUNT_ID",
    "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
    "CLOUDFLARE_API_TOKEN",
)


def _load_yaml(path: Path) -> dict:
    assert path.is_file(), f"expected workflow file at {path}"
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _raw_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _all_jobs(document: dict) -> dict:
    jobs = document.get("jobs")
    assert isinstance(jobs, dict) and jobs, "workflow must declare at least one job"
    return jobs


def _all_run_steps(document: dict) -> list[str]:
    """Return every ``run:`` step's shell text across every job."""

    scripts: list[str] = []
    for job in _all_jobs(document).values():
        for step in job.get("steps", []):
            run = step.get("run")
            if isinstance(run, str):
                scripts.append(run)
    return scripts


# ---------------------------------------------------------------------------
# Both files: basic YAML validity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", [CI_PATH, UPDATE_PATH])
def test_workflow_is_valid_yaml(path):
    document = _load_yaml(path)
    assert isinstance(document, dict)
    assert "jobs" in document


@pytest.mark.parametrize("path", [CI_PATH, UPDATE_PATH])
def test_workflow_has_a_name(path):
    document = _load_yaml(path)
    assert isinstance(document.get("name"), str) and document["name"].strip()


# ---------------------------------------------------------------------------
# ci.yml: fixture-only, no publish capability
# ---------------------------------------------------------------------------


def test_ci_has_no_publish_secrets_referenced_anywhere():
    text = _raw_text(CI_PATH)
    for secret in _PUBLISH_SECRETS:
        assert f"secrets.{secret}" not in text, (
            f"ci.yml must never reference secrets.{secret} (PR validation "
            "must not have publish credentials)"
        )


def test_ci_permissions_do_not_grant_contents_write():
    document = _load_yaml(CI_PATH)
    top_level_permissions = document.get("permissions")
    assert top_level_permissions is not None, "ci.yml must declare permissions"
    if isinstance(top_level_permissions, str):
        assert top_level_permissions == "read-all"
    else:
        assert top_level_permissions.get("contents") != "write", (
            "ci.yml (fixture-only PR validation) must not hold contents: write"
        )
    # Also check per-job permissions blocks, since a job-level block can
    # broaden beyond the workflow-level default.
    for job in _all_jobs(document).values():
        job_permissions = job.get("permissions")
        if isinstance(job_permissions, dict):
            assert job_permissions.get("contents") != "write"


def test_ci_never_runs_a_live_fetch():
    """`ru-routing fetch` without --offline-fixtures hits live upstreams.

    ci.yml must never invoke that; only `ru-routing check --fixtures` (or
    an offline-fixtures fetch) is allowed.
    """

    for script in _all_run_steps(_load_yaml(CI_PATH)):
        for line in script.splitlines():
            if "ru-routing fetch" in line:
                assert "--offline-fixtures" in line, (
                    "ci.yml must not perform a live ru-routing fetch: "
                    f"{line!r}"
                )
            if "ru-routing build" in line or "ru-routing check" in line:
                assert "--inputs" not in line, (
                    "ci.yml must build only from fixtures, never --inputs "
                    f"(a live/previously-fetched source tree): {line!r}"
                )


def test_ci_runs_fixture_driven_check():
    text = _raw_text(CI_PATH)
    assert "ru-routing check" in text
    assert "--fixtures" in text


def test_ci_triggers_on_pull_request():
    document = _load_yaml(CI_PATH)
    on = document.get(True, document.get("on"))
    assert on is not None
    assert "pull_request" in on


def test_ci_uploads_artifacts_on_failure():
    document = _load_yaml(CI_PATH)
    found = False
    for job in _all_jobs(document).values():
        for step in job.get("steps", []):
            uses = step.get("uses", "")
            if isinstance(uses, str) and "upload-artifact" in uses:
                condition = step.get("if", "")
                if "failure()" in condition:
                    found = True
    assert found, "ci.yml must upload artifacts on failure() for debugging"


def test_ci_writes_a_job_summary():
    text = _raw_text(CI_PATH)
    assert "GITHUB_STEP_SUMMARY" in text


# ---------------------------------------------------------------------------
# update.yml: hourly/manual live publication
# ---------------------------------------------------------------------------


def test_update_has_exact_hourly_cron():
    document = _load_yaml(UPDATE_PATH)
    on = document.get(True, document.get("on"))
    assert on is not None
    schedule = on.get("schedule")
    assert isinstance(schedule, list) and schedule, "update.yml needs on.schedule"
    crons = [entry.get("cron") for entry in schedule]
    assert "17 * * * *" in crons, f"expected cron '17 * * * *', got {crons!r}"


def test_update_supports_workflow_dispatch():
    document = _load_yaml(UPDATE_PATH)
    on = document.get(True, document.get("on"))
    assert "workflow_dispatch" in on


def test_update_has_a_concurrency_group():
    document = _load_yaml(UPDATE_PATH)
    concurrency = document.get("concurrency")
    assert concurrency is not None, "update.yml must declare a concurrency group"
    if isinstance(concurrency, dict):
        assert concurrency.get("group"), "concurrency group must be named"
        # Publication must not be cancelled mid-flight.
        assert concurrency.get("cancel-in-progress") is False


def test_update_permissions_are_minimal_contents_write():
    document = _load_yaml(UPDATE_PATH)
    permissions = document.get("permissions")
    assert permissions is not None, "update.yml must declare explicit permissions"
    assert isinstance(permissions, dict)
    assert permissions.get("contents") == "write"
    # Nothing broader than contents (and possibly id-token/packages for
    # Docker registry auth) should be granted at workflow level.
    unexpected = set(permissions) - {"contents", "id-token", "packages"}
    assert not unexpected, f"unexpectedly broad permissions: {unexpected}"


def test_update_has_environment_protection_on_publish_job():
    document = _load_yaml(UPDATE_PATH)
    jobs = _all_jobs(document)
    environments = [job.get("environment") for job in jobs.values()]
    assert any(environments), (
        "update.yml must reference a GitHub Actions `environment:` "
        "(e.g. production) on at least one job so repo settings can "
        "later require reviewers"
    )


def test_update_never_hardcodes_or_prints_secrets():
    """No `run:` line that echoes/prints also references a sensitive secret."""

    for script in _all_run_steps(_load_yaml(UPDATE_PATH)):
        for line in script.splitlines():
            lowered = line.lower()
            if "echo" not in lowered and "print" not in lowered:
                continue
            for secret in _PUBLISH_SECRETS:
                assert f"secrets.{secret}" not in line, (
                    f"possible secret echoed in update.yml: {line!r}"
                )


def test_update_references_secrets_and_vars_by_name_not_hardcoded():
    text = _raw_text(UPDATE_PATH)
    required_secrets = (
        "R2_ACCOUNT_ID",
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        "CLOUDFLARE_API_TOKEN",
    )
    required_vars = (
        "R2_BUCKET",
        "R2_ENDPOINT_URL",
        "CLOUDFLARE_ZONE_ID",
    )
    for secret in required_secrets:
        assert f"secrets.{secret}" in text, (
            f"update.yml must reference secrets.{secret}"
        )
    for variable in required_vars:
        assert f"vars.{variable}" in text, (
            f"update.yml must reference vars.{variable}"
        )


def test_update_never_calls_rollback():
    text = _raw_text(UPDATE_PATH)
    assert "ru-routing rollback" not in text, (
        "rollback is manual by default per the design doc -- update.yml "
        "must never invoke it automatically"
    )


def test_update_runs_live_fetch_and_real_build():
    text = _raw_text(UPDATE_PATH)
    # Commands run through the Docker builder image's `ru-routing`
    # entrypoint, so the literal subcommand (not the `ru-routing` prefix)
    # is what appears in the shell script.
    assert re.search(r"\bfetch\s+--destination\b", text)
    assert "--offline-fixtures" not in text
    assert re.search(r"\bbuild\s+--inputs\b", text)


def test_update_publish_step_is_conditionally_gated():
    """The publish step must be structurally unreachable on an unchanged run.

    We require an explicit `if:` condition on the step/job invoking
    `ru-routing publish` that references a prior step's output (not just a
    shell-level `if` inside a `run:` block), so an unchanged run genuinely
    cannot invoke publish -- not just skip it silently after invoking it.
    """

    document = _load_yaml(UPDATE_PATH)
    publish_step = None
    publish_job_if = None
    for job in _all_jobs(document).values():
        job_if = job.get("if")
        for step in job.get("steps", []):
            run = step.get("run", "")
            # The workflow invokes publish via the Docker entrypoint
            # (`ru-routing publish ...` inside `docker compose run ...
            # builder`), so the literal command in the shell script is
            # `publish --dist ...` rather than a standalone `ru-routing
            # publish` substring.
            if isinstance(run, str) and re.search(
                r"(ru-routing\s+publish|\bpublish\s+--dist\b)", run
            ):
                publish_step = step
                publish_job_if = job_if
    assert publish_step is not None, (
        "update.yml must have a step running ru-routing publish"
    )
    condition = publish_step.get("if") or publish_job_if
    assert condition, (
        "the ru-routing publish step (or its job) must have an `if:` gate "
        "so an unchanged run cannot invoke publish"
    )
    assert "steps." in condition and ".outputs." in condition, (
        "the gate must be based on a prior step's output (e.g. a "
        "release-decision/build output), not a hardcoded/always-true "
        f"condition: {condition!r}"
    )


def test_update_job_summary_present():
    text = _raw_text(UPDATE_PATH)
    assert "GITHUB_STEP_SUMMARY" in text


def test_update_uses_docker_for_the_real_build():
    text = _raw_text(UPDATE_PATH)
    assert "docker" in text.lower()


def test_update_fetches_previous_manifest_before_build():
    text = _raw_text(UPDATE_PATH)
    assert "--previous-manifest" in text
    assert "manifest.json" in text


# ---------------------------------------------------------------------------
# actionlint (best-effort; skipped if the tool truly cannot run at all)
# ---------------------------------------------------------------------------


def _actionlint_available() -> bool:
    import shutil

    return shutil.which("actionlint") is not None


@pytest.mark.skipif(not _actionlint_available(), reason="actionlint not installed")
def test_actionlint_passes():
    import subprocess

    result = subprocess.run(
        ["actionlint", str(CI_PATH), str(UPDATE_PATH)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
