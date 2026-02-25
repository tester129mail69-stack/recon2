"""Tests for godrecon.modules.screenshots (stub module)."""

from __future__ import annotations

import importlib

import pytest


def test_import_screenshots():
    mod = importlib.import_module("godrecon.modules.screenshots")
    assert mod is not None


def test_screenshots_has_docstring():
    mod = importlib.import_module("godrecon.modules.screenshots")
    assert mod.__doc__ is not None
    assert len(mod.__doc__.strip()) > 0
