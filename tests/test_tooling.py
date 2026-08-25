from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ru_routing.tooling import ToolError, ToolRunner


def test_tool_runner_passes_arguments_without_shell_interpretation(tmp_path):
    marker = tmp_path / "must-not-exist"

    result = ToolRunner(timeout_seconds=2).run(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            f"literal;touch {marker}",
        ],
        tmp_path,
    )

    assert result.argv == (
        sys.executable,
        "-c",
        "import sys; print(sys.argv[1])",
        f"literal;touch {marker}",
    )
    assert result.cwd == tmp_path
    assert result.stdout == f"literal;touch {marker}\n"
    assert result.stderr == ""
    assert result.returncode == 0
    assert not marker.exists()


def test_tool_runner_rejects_a_shell_command_string(tmp_path):
    with pytest.raises(TypeError, match="argv must be a sequence"):
        ToolRunner().run("printf unsafe", tmp_path)


def test_tool_runner_reports_timeout_with_argv_and_partial_diagnostics(tmp_path):
    with pytest.raises(ToolError) as captured:
        ToolRunner(timeout_seconds=0.05).run(
            [
                sys.executable,
                "-u",
                "-c",
                "import time; print('started'); time.sleep(1)",
            ],
            tmp_path,
        )

    message = str(captured.value)
    assert "timed out after 0.05 seconds" in message
    assert sys.executable in message
    assert "started" in message


def test_tool_runner_reports_nonzero_exit_with_stdout_and_stderr(tmp_path):
    with pytest.raises(ToolError) as captured:
        ToolRunner(timeout_seconds=2).run(
            [
                sys.executable,
                "-c",
                "import sys; print('out'); print('bad', file=sys.stderr); sys.exit(7)",
            ],
            tmp_path,
        )

    message = str(captured.value)
    assert "exited with status 7" in message
    assert "stdout:\nout" in message
    assert "stderr:\nbad" in message


@pytest.mark.parametrize(
    "argv",
    [[], ["ok", 3], ["ok", ""]],
)
def test_tool_runner_rejects_invalid_argv(argv, tmp_path):
    with pytest.raises((TypeError, ValueError)):
        ToolRunner().run(argv, tmp_path)


def test_tool_runner_requires_an_existing_directory(tmp_path):
    missing = Path(tmp_path / "missing")

    with pytest.raises(ValueError, match="working directory does not exist"):
        ToolRunner().run([sys.executable, "--version"], missing)
