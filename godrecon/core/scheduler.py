"""Async task scheduler with concurrency control, rate limiting, and retries.

Provides a priority queue–based scheduler that limits concurrency per target,
applies exponential backoff on failures, and reports progress in real time.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Awaitable, Callable, Dict, List, Optional


class Priority(IntEnum):
    """Task priority levels (lower value = higher priority)."""

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass(order=True)
class Task:
    """A unit of work managed by the scheduler.

    Attributes:
        priority: Execution priority (lower = runs first).
        name: Human-readable task identifier.
        coro_factory: Callable that returns the coroutine to execute.
        max_retries: How many times to retry on failure.
        retry_delay: Base delay in seconds for exponential backoff.
    """

    priority: int
    name: str = field(compare=False)
    coro_factory: Callable[[], Awaitable[Any]] = field(compare=False)
    max_retries: int = field(default=3, compare=False)
    retry_delay: float = field(default=1.0, compare=False)


class Scheduler:
    """Async task queue with configurable concurrency and rate limiting.

    Example::

        scheduler = Scheduler(concurrency=20, rate_limit=10)
        await scheduler.start()
        await scheduler.submit(Task(Priority.NORMAL, "dns", dns_coro_factory))
        results = await scheduler.join()
        await scheduler.stop()
    """

    def __init__(
        self,
        concurrency: int = 50,
        rate_limit: float = 0.0,
    ) -> None:
        """Initialise the scheduler.

        Args:
            concurrency: Maximum number of concurrent tasks.
            rate_limit: Minimum seconds between task starts (0 = unlimited).
        """
        self._concurrency = concurrency
        self._rate_limit = rate_limit
        self._queue: asyncio.PriorityQueue[Task] = asyncio.PriorityQueue()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._results: List[Any] = []
        self._errors: List[Dict[str, Any]] = []
        self._workers: List[asyncio.Task[None]] = []
        self._running = False
        self._last_start: float = 0.0
        self._completed = 0
        self._total = 0

    async def start(self) -> None:
        """Initialise internal semaphore and mark the scheduler as running."""
        self._semaphore = asyncio.Semaphore(self._concurrency)
        self._running = True

    async def stop(self) -> None:
        """Signal all workers to stop and wait for them to finish."""
        self._running = False
        for worker in self._workers:
            worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers.clear()

    async def submit(self, task: Task) -> None:
        """Enqueue *task* for execution.

        Args:
            task: The :class:`Task` to schedule.
        """
        self._total += 1
        await self._queue.put(task)

    async def run_all(self) -> List[Any]:
        """Process all enqueued tasks and return aggregated results.

        Returns:
            List of successful task return values.
        """
        workers = [
            asyncio.create_task(self._worker())
            for _ in range(min(self._concurrency, max(1, self._total)))
        ]
        await self._queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        return list(self._results)

    async def _worker(self) -> None:
        """Internal worker coroutine: pull tasks and execute them."""
        while True:
            task = await self._queue.get()
            try:
                await self._execute(task)
            finally:
                self._queue.task_done()

    async def _execute(self, task: Task) -> None:
        """Execute a single *task* with retry/backoff logic.

        Args:
            task: The task to execute.
        """
        assert self._semaphore is not None

        for attempt in range(task.max_retries + 1):
            async with self._semaphore:
                # Rate limiting
                if self._rate_limit > 0:
                    now = time.monotonic()
                    wait = self._rate_limit - (now - self._last_start)
                    if wait > 0:
                        await asyncio.sleep(wait)
                    self._last_start = time.monotonic()

                try:
                    result = await task.coro_factory()
                    self._results.append(result)
                    self._completed += 1
                    return
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    if attempt < task.max_retries:
                        backoff = task.retry_delay * (2 ** attempt)
                        await asyncio.sleep(backoff)
                    else:
                        self._errors.append({"task": task.name, "error": str(exc)})
                        self._completed += 1

    @property
    def completed(self) -> int:
        """Number of tasks completed (success + failure)."""
        return self._completed

    @property
    def total(self) -> int:
        """Total number of tasks submitted."""
        return self._total

    @property
    def errors(self) -> List[Dict[str, Any]]:
        """List of task error records."""
        return list(self._errors)

    @property
    def progress(self) -> float:
        """Completion percentage (0.0–100.0)."""
        if self._total == 0:
            return 0.0
        return (self._completed / self._total) * 100.0
