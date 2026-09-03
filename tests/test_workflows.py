"""Structural tests for the GitHub Actions workflows (Task 12).

These parse the actual YAML files under ``.github/workflows/`` and assert
the properties the design doc's "Change Detection and Versioning" and
"Validation and Failure Handling" sections require:

- ``ci.yml`` is fixture-only PR validation: no publish-capable permissions,
  no object-storage/GitHub-release secrets referenced anywhere, and no live
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

import os
import re
import shutil
import subprocess
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
CI_PATH = WORKFLOWS_DIR / "ci.yml"
UPDATE_PATH = WORKFLOWS_DIR / "update.yml"
DOCKERFILE_PATH = REPO_ROOT / "Dockerfile"
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"

# Secrets that must never be referenced in ci.yml (publish-capable /
# sensitive credentials only).
_PUBLISH_SECRETS = (
    "YANDEX_S3_ACCESS_KEY_ID",
    "YANDEX_S3_SECRET_ACCESS_KEY",
)
_PUBLISH_SECRET_ENV_NAMES = {*_PUBLISH_SECRETS, "GH_TOKEN"}


def test_project_declares_dev_tools_in_a_uv_dependency_group():
    project = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[dependency-groups]" in project
    assert 'dev = ["pytest", "ruff"]' in project


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


def _logical_shell_lines(script: str) -> list[str]:
    """Return non-empty shell commands with backslash continuations joined."""

    joined = re.sub(r"\\\s*\n\s*", " ", script)
    return [line.strip() for line in joined.splitlines() if line.strip()]


def _step_by_id(document: dict, step_id: str) -> dict:
    matches = [
        step
        for job in _all_jobs(document).values()
        for step in job.get("steps", [])
        if step.get("id") == step_id
    ]
    assert len(matches) == 1, f"expected exactly one step with id {step_id!r}"
    return matches[0]


def _publish_job_and_step(document: dict) -> tuple[dict, dict]:
    matches = []
    for job in _all_jobs(document).values():
        for step in job.get("steps", []):
            run = step.get("run", "")
            if isinstance(run, str) and re.search(
                r"(?:ru-routing\s+publish|\bpublish\s+--dist\b)", run
            ):
                matches.append((job, step))
    assert len(matches) == 1, "expected exactly one step invoking publish --dist"
    return matches[0]


def _secret_backed_env_names(document: dict) -> set[str]:
    names: set[str] = set()
    scopes = [document]
    for job in _all_jobs(document).values():
        scopes.append(job)
        scopes.extend(job.get("steps", []))
    for scope in scopes:
        for name, value in scope.get("env", {}).items():
            if isinstance(value, str) and re.fullmatch(
                r"\$\{\{\s*(?:secrets\.[A-Za-z_][A-Za-z0-9_]*|github\.token)\s*}}",
                value,
            ):
                names.add(name)
    return names


@contextmanager
def _http_responses(responses: list[tuple[int, bytes]]):
    requests: list[int] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib handler API
            index = min(len(requests), len(responses) - 1)
            status, body = responses[index]
            requests.append(status)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A002 - stdlib handler API
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}/manifest.json", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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
        for command in _logical_shell_lines(script):
            if "ru-routing fetch" in command:
                assert "--offline-fixtures" in command, (
                    "ci.yml must not perform a live ru-routing fetch: "
                    f"{command!r}"
                )
            if "ru-routing build" in command or "ru-routing check" in command:
                assert "--inputs" not in command, (
                    "ci.yml must build only from fixtures, never --inputs "
                    f"(a live/previously-fetched source tree): {command!r}"
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


def test_ci_installs_and_uses_locked_uv_environment():
    document = _load_yaml(CI_PATH)
    text = _raw_text(CI_PATH)
    uses = [
        step.get("uses", "")
        for job in _all_jobs(document).values()
        for step in job.get("steps", [])
    ]
    assert any(item.startswith("astral-sh/setup-uv@") for item in uses)
    assert 'version: "0.12.9"' in text
    assert "enable-cache: true" in text
    assert "uv sync --locked --group dev" in text
    assert "python -m pip install" not in text
    assert "uv run pytest -q" in text
    assert "uv run ruff check ." in text


def test_ci_downloads_a_pinned_checksum_verified_actionlint():
    script = _step_by_id(_load_yaml(CI_PATH), "actionlint")["run"]
    assert "raw.githubusercontent.com/rhysd/actionlint/main" not in script
    assert re.search(r"ACTIONLINT_VERSION=[0-9]+\.[0-9]+\.[0-9]+", script)
    assert re.search(r"ACTIONLINT_SHA256=[0-9a-f]{64}", script)
    assert "releases/download/v${ACTIONLINT_VERSION}/" in script
    assert "sha256sum -c -" in script


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
    assert permissions == {"contents": "write"}, (
        "update.yml must grant exactly contents: write and no other permission"
    )


def test_update_has_environment_protection_on_publish_job():
    document = _load_yaml(UPDATE_PATH)
    publish_job, _ = _publish_job_and_step(document)
    assert publish_job.get("environment"), (
        "the exact job invoking publish --dist must reference a GitHub Actions "
        "environment so repository protection applies to publication"
    )


def test_update_secret_backed_env_is_only_forwarded_by_name():
    """Secret values must not be shell-expanded, logged, or placed in argv."""

    document = _load_yaml(UPDATE_PATH)
    secret_env_names = _secret_backed_env_names(document)
    assert set(_PUBLISH_SECRETS) <= secret_env_names <= _PUBLISH_SECRET_ENV_NAMES
    _, publish_step = _publish_job_and_step(document)
    publish_script = " ".join(_logical_shell_lines(publish_step["run"]))

    for name in secret_env_names:
        expansion = re.compile(rf"\$(?:{re.escape(name)}\b|\{{{re.escape(name)}\}})")
        for script in _all_run_steps(document):
            assert not expansion.search(script), (
                f"secret-backed ${name} must never be expanded in run: shell text"
            )
        forwarding = re.compile(rf"(?<!\S)-e\s+{re.escape(name)}(?=\s|$)")
        assert len(forwarding.findall(publish_script)) == 1, (
            f"{name} must cross into the publish container exactly once as -e NAME"
        )
        assert name not in forwarding.sub("", publish_script), (
            f"{name} may appear in publish shell only as docker -e {name}"
        )


def test_update_references_secrets_and_vars_by_name_not_hardcoded():
    text = _raw_text(UPDATE_PATH)
    required_secrets = (
        "YANDEX_S3_ACCESS_KEY_ID",
        "YANDEX_S3_SECRET_ACCESS_KEY",
    )
    for secret in required_secrets:
        assert f"secrets.{secret}" in text, (
            f"update.yml must reference secrets.{secret}"
        )
    assert "https://storage.yandexcloud.net" in text


def test_update_has_no_legacy_object_storage_or_cdn_configuration():
    text = _raw_text(UPDATE_PATH)
    legacy_identifiers = (
        "R" + "2_ACCOUNT_ID",
        "R" + "2_ACCESS_KEY_ID",
        "R" + "2_SECRET_ACCESS_KEY",
        "R" + "2_BUCKET",
        "R" + "2_ENDPOINT_URL",
        "CLOUD" + "FLARE_ZONE_ID",
        "CLOUD" + "FLARE_API_TOKEN",
    )
    assert all(identifier not in text for identifier in legacy_identifiers)


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

    _, publish_step = _publish_job_and_step(_load_yaml(UPDATE_PATH))
    condition = re.sub(r"\s+", " ", str(publish_step.get("if", "")).strip())
    assert condition == "steps.release_decision.outputs.should_publish == 'true'", (
        "publish must be gated by exact equality with the release-decision "
        f"true output, got {condition!r}"
    )


def test_update_publish_receives_the_scoped_github_token():
    _, publish_step = _publish_job_and_step(_load_yaml(UPDATE_PATH))
    assert publish_step.get("env", {}).get("GH_TOKEN") == "${{ github.token }}"
    script = " ".join(_logical_shell_lines(publish_step["run"]))
    assert re.search(r"(?<!\S)-e\s+GH_TOKEN(?=\s|$)", script)


def test_builder_image_provides_pinned_verified_publish_clis():
    dockerfile = _raw_text(DOCKERFILE_PATH)
    for prefix in ("GH", "AWS_CLI"):
        assert re.search(rf"ARG {prefix}_VERSION=[0-9]+(?:\.[0-9]+)+", dockerfile)
        assert re.search(rf"ARG {prefix}_SHA256=[0-9a-f]{{64}}", dockerfile)
        assert f'echo "${{{prefix}_SHA256}}  ' in dockerfile
    assert "awscli-exe-linux-x86_64-${AWS_CLI_VERSION}.zip" in dockerfile
    assert "gh_${GH_VERSION}_linux_amd64.tar.gz" in dockerfile
    assert "/usr/local/bin/aws" in dockerfile
    assert "/usr/local/bin/gh" in dockerfile


def test_builder_installs_locked_runtime_dependencies_with_pinned_uv():
    dockerfile = _raw_text(DOCKERFILE_PATH)
    assert (
        "FROM ghcr.io/astral-sh/uv:0.12.9@sha256:"
        "8b940d3a9d65bed080436972241af2e21c84b5e8c9193f7014ed71479ee795ff AS uv"
        in dockerfile
    )
    assert "COPY --from=uv /uv /uvx /bin/" in dockerfile
    assert "COPY pyproject.toml uv.lock /work/" in dockerfile
    assert "uv sync --locked --no-dev --no-install-project" in dockerfile
    assert "uv sync --locked --no-dev" in dockerfile
    assert 'ENTRYPOINT ["/opt/venv/bin/ru-routing"]' in dockerfile


def test_builder_compose_entrypoint_uses_the_installed_release_cli():
    compose = _load_yaml(COMPOSE_PATH)
    assert compose["services"]["builder"]["entrypoint"] == [
        "/opt/venv/bin/ru-routing"
    ]


def test_update_preflights_publish_clis_inside_builder_image():
    scripts = _all_run_steps(_load_yaml(UPDATE_PATH))
    assert any(
        "command -v gh" in script and "command -v aws" in script
        for script in scripts
    )


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl not installed")
@pytest.mark.parametrize(
    ("responses", "expected_success", "expected_found"),
    [
        ([(404, b"not found")], True, "false"),
        ([(401, b"unauthorized")], False, None),
        ([(500, b"temporary"), (200, b'{"schema_version": 1}')], True, "true"),
        ([(200, b"not-json")], False, None),
        ([(200, b"[]")], False, None),
        ([(200, b'{"schema_version": 1}')], True, "true"),
    ],
)
def test_previous_manifest_fetch_accepts_only_valid_200_or_404(
    tmp_path, responses, expected_success, expected_found
):
    script = _step_by_id(_load_yaml(UPDATE_PATH), "previous_manifest")["run"]
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    github_output = tmp_path / "github-output"
    with _http_responses(responses) as (url, requests):
        result = subprocess.run(
            ["bash", "-c", script],
            cwd=tmp_path,
            env={
                **os.environ,
                "GITHUB_OUTPUT": str(github_output),
                "MANIFEST_URL": url,
            },
            capture_output=True,
            text=True,
            timeout=15,
        )

    assert (result.returncode == 0) is expected_success, result.stdout + result.stderr
    output_text = (
        github_output.read_text(encoding="utf-8")
        if github_output.exists()
        else ""
    )
    if expected_found is None:
        assert "found=" not in output_text
        assert not (output_dir / "previous-manifest.json").exists()
    else:
        assert f"found={expected_found}" in output_text
        assert (output_dir / "previous-manifest.json").exists() is (
            expected_found == "true"
        )
    if len(responses) > 1:
        assert len(requests) >= len(responses), (
            "transient HTTP failures must be retried"
        )


def test_update_retains_stage_logs_and_partial_build_outputs_on_failure():
    document = _load_yaml(UPDATE_PATH)
    publish_job, _ = _publish_job_and_step(document)
    scripts = _all_run_steps(document)
    for command, log_path in (
        (r"\bfetch\s+--destination\b", "output/fetch.log"),
        (r"\bbuild\s+--inputs\b", "output/build.log"),
        (r"\bpublish\s+--dist\b", "output/publish.log"),
    ):
        script = next(script for script in scripts if re.search(command, script))
        assert "pipefail" in script
        assert re.search(rf"2>&1\s*\|\s*tee\s+{re.escape(log_path)}", script)

    upload_steps = [
        step
        for step in publish_job.get("steps", [])
        if "upload-artifact" in str(step.get("uses", ""))
        and "failure()" in str(step.get("if", ""))
    ]
    assert len(upload_steps) == 1
    retained_paths = str(upload_steps[0].get("with", {}).get("path", ""))
    for path in ("output/fetch.log", "output/build.log", "output/publish.log"):
        assert path in retained_paths
    assert "output/dist/" in retained_paths


def test_update_job_summary_present():
    text = _raw_text(UPDATE_PATH)
    assert "GITHUB_STEP_SUMMARY" in text


def test_update_summary_discloses_degraded_sources():
    summary = _step_by_id(_load_yaml(UPDATE_PATH), "summary")["run"]
    assert "degraded_sources" in summary


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
    return shutil.which("actionlint") is not None


@pytest.mark.skipif(not _actionlint_available(), reason="actionlint not installed")
def test_actionlint_passes():
    result = subprocess.run(
        ["actionlint", str(CI_PATH), str(UPDATE_PATH)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
