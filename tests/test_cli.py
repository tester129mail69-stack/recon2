"""Tests for godrecon.cli."""

from __future__ import annotations

import typer
from typer.testing import CliRunner

from godrecon.cli import app, main


def test_app_is_typer_instance() -> None:
    """The CLI app object should be a Typer instance."""
    assert isinstance(app, typer.Typer)


def test_main_is_callable() -> None:
    """The main() entry point should be callable."""
    assert callable(main)


def test_version_command() -> None:
    """The version command should exit cleanly and display version info."""
    runner = CliRunner()
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "GODRECON" in result.output or "godrecon" in result.output.lower()


def test_config_command() -> None:
    """The config command should exit cleanly."""
    runner = CliRunner()
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0


def test_scan_help() -> None:
    """The scan command --help should exit cleanly."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "target" in result.output.lower()
