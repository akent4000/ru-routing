from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap-yandex-storage.sh"


FAKE_CURL = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state = json.loads(Path(os.environ["FAKE_STATE"]).read_text())
argv = sys.argv[1:]
with Path(os.environ["FAKE_TOOL_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "curl", "argv": argv}) + "\n")

output = argv[argv.index("--output") + 1]
Path(output).write_text(state["manifest_body"], encoding="utf-8")
sys.stdout.write(str(state["manifest_status"]))
sys.exit(state.get("curl_exit", 0))
'''


FAKE_AWS = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

argv = sys.argv[1:]
with Path(os.environ["FAKE_TOOL_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "aws", "argv": argv}) + "\n")
expected = [
    "s3api", "head-bucket", "--bucket", "routing.akent.site", "--endpoint-url",
    "https://storage.yandexcloud.net",
]
credentials_present = bool(
    os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY")
)
sys.exit(0 if argv == expected and credentials_present else 1)
'''


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state = json.loads(Path(os.environ["FAKE_STATE"]).read_text())
argv = sys.argv[1:]
with Path(os.environ["FAKE_TOOL_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "gh", "argv": argv}) + "\n")

if argv[:1] == ["api"]:
    sys.exit(0 if state["environment"] else 1)
if argv[:2] == ["secret", "list"]:
    sys.stdout.write("\n".join(state["secrets"]))
    sys.exit(0)
sys.exit(2)
'''


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


@pytest.fixture
def bootstrap_env(tmp_path: Path) -> tuple[dict[str, str], Path, Path]:
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    _write_executable(fake_bin / "curl", FAKE_CURL)
    _write_executable(fake_bin / "aws", FAKE_AWS)
    _write_executable(fake_bin / "gh", FAKE_GH)

    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps(
            {
                "manifest_status": 404,
                "manifest_body": "not found",
                "environment": True,
                "secrets": [
                    "YANDEX_S3_ACCESS_KEY_ID",
                    "YANDEX_S3_SECRET_ACCESS_KEY",
                ],
            }
        ),
        encoding="utf-8",
    )
    log_path = tmp_path / "tools.jsonl"
    return (
        {
            **os.environ,
            "PATH": f"{fake_bin}:{os.environ['PATH']}",
            "FAKE_STATE": str(state_path),
            "FAKE_TOOL_LOG": str(log_path),
            "GITHUB_REPOSITORY": "owner/routing",
            "YANDEX_S3_ACCESS_KEY_ID": "TEST_YANDEX_ACCESS_KEY",
            "YANDEX_S3_SECRET_ACCESS_KEY": "TEST_YANDEX_SECRET_KEY",
        },
        state_path,
        log_path,
    )


def _run(env: dict[str, str], *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(SCRIPT), *arguments],
        cwd=ROOT,
        env=env,
        capture_output=True,
        check=False,
        text=True,
    )


def _tool_calls(log_path: Path) -> list[dict[str, object]]:
    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines()]


@pytest.mark.parametrize(
    ("status", "body"),
    [(404, "not found"), (200, '{"schema_version": 1}')],
)
def test_check_accepts_first_release_or_valid_manifest(
    bootstrap_env: tuple[dict[str, str], Path, Path], status: int, body: str
) -> None:
    """A bad endpoint status or manifest body must not be accepted as readiness."""

    env, state_path, log_path = bootstrap_env
    state = json.loads(state_path.read_text())
    state["manifest_status"] = status
    state["manifest_body"] = body
    state_path.write_text(json.dumps(state), encoding="utf-8")

    completed = _run(env, "--check")

    assert completed.returncode == 0, completed.stderr
    calls = _tool_calls(log_path)
    assert [call["tool"] for call in calls] == ["curl", "aws", "gh", "gh"]


@pytest.mark.parametrize(
    ("status", "body"),
    [(200, "not json"), (401, "unauthorized"), (500, "server error")],
)
def test_check_rejects_invalid_endpoint_without_leaking_credentials(
    bootstrap_env: tuple[dict[str, str], Path, Path], status: int, body: str
) -> None:
    """Readiness must fail closed without putting credential values in output."""

    env, state_path, log_path = bootstrap_env
    env["YANDEX_S3_ACCESS_KEY_ID"] = "ACCESS_SENTINEL_DO_NOT_PRINT"
    env["YANDEX_S3_SECRET_ACCESS_KEY"] = "SECRET_SENTINEL_DO_NOT_PRINT"
    state = json.loads(state_path.read_text())
    state["manifest_status"] = status
    state["manifest_body"] = body
    state_path.write_text(json.dumps(state), encoding="utf-8")

    completed = _run(env, "--check")

    assert completed.returncode != 0
    observable = completed.stdout + completed.stderr + log_path.read_text()
    assert "ACCESS_SENTINEL_DO_NOT_PRINT" not in observable
    assert "SECRET_SENTINEL_DO_NOT_PRINT" not in observable


def test_check_is_read_only_and_uses_yandex_s3(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    """A check must not create or configure user-owned infrastructure."""

    env, _, log_path = bootstrap_env

    completed = _run(env, "--check")

    assert completed.returncode == 0, completed.stderr
    for call in _tool_calls(log_path):
        argv = call["argv"]
        assert not any(method in argv for method in ("POST", "PUT", "PATCH", "DELETE"))
        assert argv[:2] not in (["secret", "set"], ["variable", "set"])


def test_check_requires_both_yandex_environment_secrets(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    """A missing production secret would make the publish workflow unusable."""

    env, state_path, _ = bootstrap_env
    state = json.loads(state_path.read_text())
    state["secrets"] = ["YANDEX_S3_ACCESS_KEY_ID"]
    state_path.write_text(json.dumps(state), encoding="utf-8")

    completed = _run(env, "--check")

    assert completed.returncode != 0
    assert "YANDEX_S3_SECRET_ACCESS_KEY" in completed.stderr


@pytest.mark.parametrize(
    "missing",
    ["GITHUB_REPOSITORY", "YANDEX_S3_ACCESS_KEY_ID", "YANDEX_S3_SECRET_ACCESS_KEY"],
)
def test_check_fails_before_external_calls_when_runtime_input_is_missing(
    bootstrap_env: tuple[dict[str, str], Path, Path], missing: str
) -> None:
    env, _, log_path = bootstrap_env
    env.pop(missing)

    completed = _run(env, "--check")

    assert completed.returncode != 0
    assert missing in completed.stderr
    assert _tool_calls(log_path) == []


def test_permissions_explain_user_owned_infrastructure() -> None:
    completed = subprocess.run(
        [str(SCRIPT), "--permissions"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0
    assert "storage.editor" in completed.stdout
    assert "bucket" in completed.stdout.lower()
    assert "DNS" in completed.stdout
    assert "certificate" in completed.stdout.lower()


def test_help_documents_read_only_check() -> None:
    completed = subprocess.run(
        [str(SCRIPT), "--help"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0
    assert "--check" in completed.stdout
    assert "read-only" in completed.stdout.lower()


def test_readme_documents_yandex_runtime_contract() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Yandex Object Storage" in readme
    assert "routing.akent.site" in readme
    assert "storage.editor" in readme
    assert "YANDEX_S3_ACCESS_KEY_ID" in readme
    assert "YANDEX_S3_SECRET_ACCESS_KEY" in readme
    assert "https://storage.yandexcloud.net" in readme
    assert "404" in readme

    for obsolete in (
        "Cloudflare",
        "R2_ACCOUNT_ID",
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        "R2_BUCKET",
        "R2_ENDPOINT_URL",
        "CLOUDFLARE_ZONE_ID",
        "CLOUDFLARE_API_TOKEN",
        "bootstrap-cloudflare.sh",
    ):
        assert obsolete not in readme


def test_readme_documents_locked_uv_development_setup() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "uv sync --locked --group dev" in readme
    assert "uv run pytest -q" in readme
    assert "python -m pip install -e . pytest ruff" not in readme
