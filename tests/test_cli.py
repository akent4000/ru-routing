import pytest

from ru_routing.cli import main


def test_cli_exposes_pipeline_commands(capsys):
    assert main(["--help"]) == 0

    output = capsys.readouterr().out
    commands = ["fetch", "build", "check", "publish", "rollback"]
    assert all(command in output for command in commands)


@pytest.mark.parametrize("command", ["fetch", "build", "check", "publish", "rollback"])
def test_pipeline_commands_report_that_they_are_not_wired(command, capsys):
    assert main([command]) == 2

    assert f"{command} is not wired yet" in capsys.readouterr().err
