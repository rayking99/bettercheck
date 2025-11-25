# tests/test_cli.py
from click.testing import CliRunner
from bettercheck.cli import main
import pytest


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.output


def test_cli_invalid_package():
    runner = CliRunner()
    result = runner.invoke(main, ["invalid/package/name"])
    # Should handle invalid package name gracefully
    assert result.exit_code != 0 or "Error" in result.output or "Invalid" in result.output


def test_cli_with_json_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "--json" in result.output


def test_cli_with_debug_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "--debug" in result.output


def test_cli_with_report_flag():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert "--report" in result.output
