from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap-cloudflare.sh"


FAKE_CURL = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


state_path = Path(os.environ["FAKE_STATE"])
log_path = Path(os.environ["FAKE_TOOL_LOG"])
state = json.loads(state_path.read_text())
argv = sys.argv[1:]
with log_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "curl", "argv": argv}) + "\n")


def option_value(*names):
    for index, argument in enumerate(argv):
        if argument in names:
            return argv[index + 1]
    return None


def request_body():
    value = option_value("--data-binary", "--data")
    if value is None:
        return None
    if value.startswith("@"):
        return json.loads(Path(value[1:]).read_text())
    return json.loads(value)


method = option_value("--request", "-X") or "GET"
output_path = option_value("--output", "-o")
url = next(argument for argument in argv if argument.startswith("https://"))
status = int(os.environ.get("FAKE_CURL_FORCE_STATUS", "0"))
response = {"success": False, "errors": [{"message": "not found"}]}

account = os.environ["CLOUDFLARE_ACCOUNT_ID"]
zone = os.environ["CLOUDFLARE_ZONE_ID"]
bucket = os.environ["R2_BUCKET"]
domain = os.environ.get("ROUTING_DOMAIN", "routing.akent.site")
api = "https://api.cloudflare.com/client/v4"
bucket_url = f"{api}/accounts/{account}/r2/buckets/{bucket}"
domain_url = f"{bucket_url}/domains/custom/{domain}"
rulesets_url = f"{api}/zones/{zone}/rulesets"
entrypoint_url = f"{rulesets_url}/phases/http_request_cache_settings/entrypoint"

if not status:
    if url == bucket_url and method == "GET":
        if state["bucket"]:
            status = 200
            response = {"success": True, "result": {"name": bucket}}
        else:
            status = 404
    elif url == bucket_url.rsplit("/", 1)[0] and method == "POST":
        body = request_body()
        state["bucket"] = True
        status = 200
        response = {"success": True, "result": {"name": body["name"]}}
    elif url == domain_url and method == "GET":
        if state["domain"] is None:
            status = 404
        else:
            status = 200
            response = {"success": True, "result": state["domain"]}
    elif url == f"{bucket_url}/domains/custom" and method == "POST":
        body = request_body()
        state["domain"] = {
            **body,
            "status": {"ownership": "active", "ssl": "active"},
        }
        status = 200
        response = {"success": True, "result": body}
    elif url == entrypoint_url and method == "GET":
        if state["ruleset"] is None:
            status = 404
        else:
            status = 200
            response = {"success": True, "result": state["ruleset"]}
    elif url == rulesets_url and method == "POST":
        body = request_body()
        rules = []
        for index, rule in enumerate(body["rules"], start=1):
            rules.append({**rule, "id": f"rule-{index}"})
        state["ruleset"] = {**body, "id": "ruleset-1", "rules": rules}
        status = 200
        response = {"success": True, "result": state["ruleset"]}
    elif url == f"{rulesets_url}/ruleset-1/rules" and method == "POST":
        body = request_body()
        rule = {**body, "id": f"rule-{len(state['ruleset']['rules']) + 1}"}
        state["ruleset"]["rules"].append(rule)
        status = 200
        response = {"success": True, "result": rule}
    elif url.startswith(f"{rulesets_url}/ruleset-1/rules/") and method == "PATCH":
        body = request_body()
        rule_id = url.rsplit("/", 1)[1]
        state["ruleset"]["rules"] = [
            {**body, "id": rule_id} if rule["id"] == rule_id else rule
            for rule in state["ruleset"]["rules"]
        ]
        status = 200
        response = {"success": True, "result": {**body, "id": rule_id}}
    else:
        status = 500
        response = {"success": False, "errors": [{"message": "unexpected call"}]}

state_path.write_text(json.dumps(state), encoding="utf-8")
if output_path:
    Path(output_path).write_text(json.dumps(response), encoding="utf-8")
if "--write-out" in argv:
    sys.stdout.write(str(status))
sys.exit(0)
'''


FAKE_AWS = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


argv = sys.argv[1:]
with Path(os.environ["FAKE_TOOL_LOG"]).open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "aws", "argv": argv}) + "\n")
state = json.loads(Path(os.environ["FAKE_STATE"]).read_text())
credentials_present = bool(
    os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY")
)
expected = ["s3api", "head-bucket"]
sys.exit(0 if argv[:2] == expected and state["bucket"] and credentials_present else 1)
'''


FAKE_GH = r'''#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path


state_path = Path(os.environ["FAKE_STATE"])
log_path = Path(os.environ["FAKE_TOOL_LOG"])
state = json.loads(state_path.read_text())
argv = sys.argv[1:]
with log_path.open("a", encoding="utf-8") as handle:
    handle.write(json.dumps({"tool": "gh", "argv": argv}) + "\n")


def option_value(*names):
    for index, argument in enumerate(argv):
        if argument in names:
            return argv[index + 1]
    return None


status = 0
if argv[:1] == ["api"]:
    method = option_value("--method", "-X") or "GET"
    if method == "GET":
        status = 0 if state["environment"] else 1
        if not status:
            print(json.dumps({"name": "production"}))
    elif method == "PUT":
        state["environment"] = True
        print(json.dumps({"name": "production"}))
    else:
        status = 2
elif argv[:2] == ["secret", "list"]:
    print(json.dumps([{"name": name} for name in sorted(state["secrets"])]))
elif argv[:2] == ["secret", "set"]:
    sys.stdin.read()
    name = argv[2]
    if name not in state["secrets"]:
        state["secrets"].append(name)
elif argv[:2] == ["variable", "list"]:
    print(
        json.dumps(
            [
                {"name": name, "value": value}
                for name, value in sorted(state["variables"].items())
            ]
        )
    )
elif argv[:2] == ["variable", "set"]:
    state["variables"][argv[2]] = option_value("--body", "-b")
else:
    status = 2

state_path.write_text(json.dumps(state), encoding="utf-8")
sys.exit(status)
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
                "bucket": False,
                "domain": None,
                "ruleset": None,
                "environment": False,
                "secrets": [],
                "variables": {},
            }
        ),
        encoding="utf-8",
    )
    log_path = tmp_path / "tools.jsonl"
    env = {
        **os.environ,
        "PATH": f"{fake_bin}:{os.environ['PATH']}",
        "FAKE_STATE": str(state_path),
        "FAKE_TOOL_LOG": str(log_path),
        "CLOUDFLARE_API_TOKEN": "TEST_BOOTSTRAP_TOKEN_VALUE",
        "CLOUDFLARE_ACCOUNT_ID": "account-test",
        "CLOUDFLARE_ZONE_ID": "zone-test",
        "R2_BUCKET": "routing-test",
        "GITHUB_REPOSITORY": "owner/routing",
        "R2_ACCESS_KEY_ID": "TEST_R2_ACCESS_VALUE",
        "R2_SECRET_ACCESS_KEY": "TEST_R2_SECRET_VALUE",
        "CLOUDFLARE_CACHE_PURGE_TOKEN": "TEST_PURGE_TOKEN_VALUE",
    }
    return env, state_path, log_path


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


def _prepare(bootstrap_env: tuple[dict[str, str], Path, Path]) -> None:
    env, _, _ = bootstrap_env
    completed = _run(env, "--apply")
    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "missing",
    [
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_ZONE_ID",
        "R2_BUCKET",
        "GITHUB_REPOSITORY",
    ],
)
def test_missing_required_variable_fails_before_external_calls(
    bootstrap_env: tuple[dict[str, str], Path, Path], missing: str
) -> None:
    env, _, log_path = bootstrap_env
    env.pop(missing)

    completed = _run(env, "--check")

    assert completed.returncode != 0
    assert missing in completed.stderr
    assert _tool_calls(log_path) == []


def test_permissions_explain_distinct_least_privilege_tokens() -> None:
    completed = subprocess.run(
        [str(SCRIPT), "--permissions"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0
    assert "Workers R2 Storage Write" in completed.stdout
    assert "Cache Rules Edit" in completed.stdout
    assert "Cache Purge" in completed.stdout
    assert "Object Read & Write" in completed.stdout
    assert "specific bucket" in completed.stdout
    assert "separate" in completed.stdout.lower()


def test_apply_uses_scoped_boundaries_and_is_idempotent(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    env, _, log_path = bootstrap_env

    first = _run(env, "--apply")

    assert first.returncode == 0, first.stderr
    calls = _tool_calls(log_path)
    curl_calls = [call["argv"] for call in calls if call["tool"] == "curl"]
    assert any(
        "https://api.cloudflare.com/client/v4/accounts/account-test/r2/buckets"
        in argv
        and "POST" in argv
        for argv in curl_calls
    )
    assert any(
        "/accounts/account-test/r2/buckets/routing-test/domains/custom" in " ".join(
            argv
        )
        and "POST" in argv
        for argv in curl_calls
    )
    assert any(
        "/zones/zone-test/rulesets" in " ".join(argv) and "POST" in argv
        for argv in curl_calls
    )
    aws_calls = [call["argv"] for call in calls if call["tool"] == "aws"]
    assert any(
        argv[:2] == ["s3api", "head-bucket"]
        and argv[argv.index("--bucket") + 1] == "routing-test"
        and argv[argv.index("--endpoint-url") + 1]
        == "https://account-test.r2.cloudflarestorage.com"
        for argv in aws_calls
    )
    gh_calls = [call["argv"] for call in calls if call["tool"] == "gh"]
    assert {
        argv[2]
        for argv in gh_calls
        if argv[:2] == ["secret", "set"]
    } == {
        "R2_ACCOUNT_ID",
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        "CLOUDFLARE_API_TOKEN",
    }

    log_path.write_text("", encoding="utf-8")
    second = _run(env, "--apply")

    assert second.returncode == 0, second.stderr
    second_calls = _tool_calls(log_path)
    for call in second_calls:
        argv = call["argv"]
        if call["tool"] == "curl":
            mutation_methods = ["POST", "PUT", "PATCH", "DELETE"]
            assert not any(method in argv for method in mutation_methods)
        if call["tool"] == "gh":
            assert argv[:2] not in (["secret", "set"], ["variable", "set"])
            assert not (argv[:1] == ["api"] and "PUT" in argv)


def test_check_is_read_only_when_everything_matches(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    env, _, log_path = bootstrap_env
    _prepare(bootstrap_env)
    log_path.write_text("", encoding="utf-8")

    completed = _run(env, "--check")

    assert completed.returncode == 0, completed.stderr
    assert "verified" in completed.stdout.lower()
    calls = _tool_calls(log_path)
    assert all(
        not any(method in call["argv"] for method in ["POST", "PUT", "PATCH", "DELETE"])
        for call in calls
        if call["tool"] == "curl"
    )
    assert all(
        call["argv"][:2] not in (["secret", "set"], ["variable", "set"])
        for call in calls
        if call["tool"] == "gh"
    )


def test_check_rejects_custom_domain_that_is_not_fully_active(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    env, state_path, _ = bootstrap_env
    _prepare(bootstrap_env)
    state = json.loads(state_path.read_text())
    state["domain"]["status"]["ssl"] = "pending"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    completed = _run(env, "--check")

    assert completed.returncode != 0
    assert "custom domain" in completed.stderr.lower()
    assert "active" in completed.stderr.lower()


def test_check_rejects_drifted_cache_rule(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    env, state_path, _ = bootstrap_env
    _prepare(bootstrap_env)
    state = json.loads(state_path.read_text())
    state["ruleset"]["rules"][0]["action_parameters"]["edge_ttl"]["default"] = 60
    state_path.write_text(json.dumps(state), encoding="utf-8")

    completed = _run(env, "--check")

    assert completed.returncode != 0
    assert "cache rule" in completed.stderr.lower()
    assert "drift" in completed.stderr.lower()


def test_secret_values_are_neither_printed_nor_passed_in_argv(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    env, _, log_path = bootstrap_env

    completed = _run(env, "--apply")

    assert completed.returncode == 0, completed.stderr
    observable = completed.stdout + completed.stderr + log_path.read_text()
    for name in [
        "CLOUDFLARE_API_TOKEN",
        "R2_ACCESS_KEY_ID",
        "R2_SECRET_ACCESS_KEY",
        "CLOUDFLARE_CACHE_PURGE_TOKEN",
    ]:
        assert env[name] not in observable


def test_cloudflare_http_failure_reports_status_without_response_body_or_token(
    bootstrap_env: tuple[dict[str, str], Path, Path]
) -> None:
    env, _, _ = bootstrap_env
    env["FAKE_CURL_FORCE_STATUS"] = "500"

    completed = _run(env, "--check")

    assert completed.returncode != 0
    assert "HTTP 500" in completed.stderr
    assert "not found" not in completed.stderr
    assert env["CLOUDFLARE_API_TOKEN"] not in completed.stderr
