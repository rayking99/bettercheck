# tests/test_cli.py
from click.testing import CliRunner
from bettercheck.cli import main
import pytest


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output


@pytest.mark.vcr
def test_cli_package_check():
    runner = CliRunner()
    result = runner.invoke(main, ["requests"])
    assert result.exit_code == 0
