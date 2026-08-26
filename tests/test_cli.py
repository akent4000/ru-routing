from pathlib import Path

import pytest

from ru_routing.cli import main


def test_cli_exposes_pipeline_commands(capsys):
    assert main(["--help"]) == 0

    output = capsys.readouterr().out
    commands = ["fetch", "build", "check", "release-decision", "publish", "rollback"]
    assert all(command in output for command in commands)


@pytest.mark.parametrize("command", ["publish", "rollback"])
def test_publish_and_rollback_report_that_they_are_not_yet_implemented(
    command, capsys
):
    assert main([command]) == 3

    error = capsys.readouterr().err
    assert "not yet implemented" in error
    assert "Task 11" in error


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
