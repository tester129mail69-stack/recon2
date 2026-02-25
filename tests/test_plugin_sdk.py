"""Tests for godrecon.core.plugin_sdk."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from godrecon.core.plugin_sdk import create_module_scaffold


def test_scaffold_creates_directory(tmp_path: Path) -> None:
    """create_module_scaffold should create the module directory."""
    result = create_module_scaffold("my_module", str(tmp_path))
    assert Path(result).is_dir()


def test_scaffold_returns_correct_path(tmp_path: Path) -> None:
    """The returned path should be <output_dir>/<module_name>."""
    result = create_module_scaffold("my_module", str(tmp_path))
    assert Path(result) == tmp_path / "my_module"


def test_scaffold_creates_init_file(tmp_path: Path) -> None:
    """__init__.py should be created with the module docstring."""
    create_module_scaffold("my_module", str(tmp_path))
    init_file = tmp_path / "my_module" / "__init__.py"
    assert init_file.exists()
    content = init_file.read_text()
    assert "my_module" in content


def test_scaffold_creates_scanner_file(tmp_path: Path) -> None:
    """scanner.py should be created."""
    create_module_scaffold("my_module", str(tmp_path))
    scanner_file = tmp_path / "my_module" / "scanner.py"
    assert scanner_file.exists()


def test_scaffold_scanner_has_class(tmp_path: Path) -> None:
    """scanner.py should contain the CamelCase class definition."""
    create_module_scaffold("my_module", str(tmp_path))
    scanner_file = tmp_path / "my_module" / "scanner.py"
    content = scanner_file.read_text()
    assert "class MyModuleModule(BaseModule):" in content


def test_scaffold_scanner_has_execute(tmp_path: Path) -> None:
    """scanner.py should define the _execute method."""
    create_module_scaffold("my_module", str(tmp_path))
    scanner_file = tmp_path / "my_module" / "scanner.py"
    content = scanner_file.read_text()
    assert "_execute" in content
    assert "ModuleResult" in content


def test_scaffold_scanner_uses_category_and_author(tmp_path: Path) -> None:
    """Category and author should appear in the generated scanner."""
    create_module_scaffold("my_module", str(tmp_path), category="recon", author="Alice")
    scanner_file = tmp_path / "my_module" / "scanner.py"
    content = scanner_file.read_text()
    assert 'category = "recon"' in content
    assert 'author = "Alice"' in content


def test_scaffold_multiword_name(tmp_path: Path) -> None:
    """Multi-word names (with underscores) should produce correct CamelCase class."""
    create_module_scaffold("foo_bar_baz", str(tmp_path))
    scanner_file = tmp_path / "foo_bar_baz" / "scanner.py"
    content = scanner_file.read_text()
    assert "class FooBarBazModule(BaseModule):" in content


def test_scaffold_invalid_name_raises(tmp_path: Path) -> None:
    """Invalid module names should raise ValueError."""
    invalid_names = ["MyModule", "123module", "my-module", "my module", ""]
    for name in invalid_names:
        with pytest.raises(ValueError, match="Invalid module name"):
            create_module_scaffold(name, str(tmp_path))


def test_scaffold_valid_single_char_name(tmp_path: Path) -> None:
    """A single lowercase letter is a valid module name."""
    result = create_module_scaffold("a", str(tmp_path))
    assert Path(result).is_dir()


def test_scaffold_idempotent(tmp_path: Path) -> None:
    """Calling scaffold twice should not raise (exist_ok=True)."""
    create_module_scaffold("my_module", str(tmp_path))
    # Should not raise
    create_module_scaffold("my_module", str(tmp_path))
