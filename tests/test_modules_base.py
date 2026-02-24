"""Tests for godrecon.modules.base."""

from __future__ import annotations

import pytest

from godrecon.core.config import Config
from godrecon.modules.base import BaseModule, Finding, ModuleResult


def test_base_module_is_abstract():
    """BaseModule cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseModule()  # type: ignore[abstract]


def test_finding_defaults():
    f = Finding(title="Test Finding")
    assert f.severity == "info"
    assert f.data == {}
    assert f.tags == []


def test_module_result_defaults():
    mr = ModuleResult(module_name="test", target="example.com")
    assert mr.findings == []
    assert mr.error is None
    assert mr.duration == 0.0


class _ConcreteModule(BaseModule):
    name = "test_module"
    description = "A test module"
    category = "test"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=[Finding(title="found something")],
        )


def test_concrete_module_instantiates():
    mod = _ConcreteModule()
    assert mod.name == "test_module"
    assert repr(mod) == "<Module test_module v0.1.0>"


@pytest.mark.asyncio
async def test_concrete_module_run():
    mod = _ConcreteModule()
    result = await mod.run("example.com", Config())
    assert result.module_name == "test_module"
    assert result.target == "example.com"
    assert len(result.findings) == 1
    assert result.findings[0].title == "found something"
    assert result.duration >= 0


@pytest.mark.asyncio
async def test_module_run_captures_exceptions():
    """BaseModule.run returns an error result instead of raising."""

    class _FailingModule(BaseModule):
        name = "failing"
        description = "Always fails"
        category = "test"

        async def _execute(self, target: str, config: Config) -> ModuleResult:
            raise RuntimeError("something broke")

    mod = _FailingModule()
    result = await mod.run("example.com", Config())
    assert result.error == "something broke"
    assert result.findings == []
