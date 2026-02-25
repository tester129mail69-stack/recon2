"""Tests for godrecon.core.scheduler."""

from __future__ import annotations

import asyncio

import pytest

from godrecon.core.scheduler import Priority, Scheduler, Task


def test_priority_enum_values() -> None:
    """Priority enum should have HIGH, NORMAL, and LOW members."""
    assert Priority.HIGH < Priority.NORMAL
    assert Priority.NORMAL < Priority.LOW


def test_task_dataclass() -> None:
    """Task dataclass should store all fields correctly."""
    async def dummy() -> str:
        return "ok"

    task = Task(priority=int(Priority.NORMAL), name="test", coro_factory=dummy)
    assert task.name == "test"
    assert task.priority == int(Priority.NORMAL)
    assert task.max_retries == 3


def test_scheduler_instantiation() -> None:
    """Scheduler should instantiate without errors."""
    scheduler = Scheduler(concurrency=5)
    assert scheduler.total == 0
    assert scheduler.completed == 0


@pytest.mark.asyncio
async def test_scheduler_runs_simple_task() -> None:
    """Scheduler should execute a simple async task and return its result."""
    results: list[str] = []

    async def simple_task() -> None:
        results.append("done")

    scheduler = Scheduler(concurrency=2)
    await scheduler.start()
    await scheduler.submit(
        Task(priority=int(Priority.NORMAL), name="simple", coro_factory=simple_task)
    )
    await scheduler.run_all()
    await scheduler.stop()

    assert results == ["done"]
