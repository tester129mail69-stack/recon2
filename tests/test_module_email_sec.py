"""Tests for godrecon.modules.email_sec (stub module)."""

from __future__ import annotations

import importlib

import pytest


def test_import_email_sec():
    mod = importlib.import_module("godrecon.modules.email_sec")
    assert mod is not None


def test_email_sec_has_docstring():
    mod = importlib.import_module("godrecon.modules.email_sec")
    assert mod.__doc__ is not None
    assert len(mod.__doc__.strip()) > 0
