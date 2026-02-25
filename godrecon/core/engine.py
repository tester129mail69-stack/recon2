"""Main scan orchestrator for GODRECON.

The :class:`ScanEngine` discovers and loads all enabled modules, runs them
concurrently via :class:`~godrecon.core.scheduler.Scheduler`, and aggregates
the results.
"""

from __future__ import annotations

import asyncio
import importlib
import pkgutil
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config, load_config
from godrecon.core.scheduler import Priority, Scheduler, Task
from godrecon.core.scope import ScopeManager
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ScanResult:
    """Aggregated results from a complete scan.

    Attributes:
        target: The primary scan target.
        started_at: Unix timestamp when the scan began.
        finished_at: Unix timestamp when the scan ended (or ``None``).
        module_results: Mapping of module name to its result data.
        errors: List of error records encountered during scanning.
        stats: Summary statistics dictionary.
    """

    target: str
    started_at: float
    finished_at: Optional[float] = None
    module_results: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Elapsed scan time in seconds."""
        if self.finished_at is None:
            return time.time() - self.started_at
        return self.finished_at - self.started_at


class ScanEngine:
    """Orchestrates the full reconnaissance scan lifecycle.

    Discovers all enabled modules, schedules them concurrently, collects
    results, and fires real-time events for external consumers (e.g. the CLI
    progress display).

    Example::

        engine = ScanEngine(target="example.com")
        result = await engine.run()
        print(result.module_results)
    """

    def __init__(
        self,
        target: str,
        config: Optional[Config] = None,
        config_path: Optional[str] = None,
    ) -> None:
        """Initialise the scan engine.

        Args:
            target: Primary scan target (domain, IP, or CIDR).
            config: Pre-built :class:`~godrecon.core.config.Config` object. If
                    ``None`` the configuration is loaded from *config_path*.
            config_path: Optional path to a YAML configuration file.
        """
        self.target = target
        self.config: Config = config or load_config(config_path)
        self.scope = ScopeManager()
        self.scope.add_target(target)
        self._event_handlers: List[Any] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def on_event(self, handler: Any) -> None:
        """Register a callable to receive real-time scan events.

        Args:
            handler: An async or sync callable that accepts a ``dict`` event.
        """
        self._event_handlers.append(handler)

    async def run(self) -> ScanResult:
        """Execute the full scan and return aggregated results.

        Returns:
            :class:`ScanResult` containing data from all executed modules.
        """
        result = ScanResult(target=self.target, started_at=time.time())
        await self._emit({"event": "scan_started", "target": self.target})

        modules = self._load_modules()
        if not modules:
            logger.warning("No modules loaded for target: %s", self.target)
            result.finished_at = time.time()
            return result

        logger.info("Loaded %d modules for target: %s", len(modules), self.target)

        scheduler = Scheduler(
            concurrency=self.config.general.threads,
        )
        await scheduler.start()

        # Subdomains first so alert fires before vuln scanning begins
        subdomain_modules = [m for m in modules if m.name == "subdomains"]
        other_modules = [m for m in modules if m.name != "subdomains"]

        for module in subdomain_modules:
            task = Task(
                priority=int(Priority.HIGH),
                name=module.name,
                coro_factory=lambda m=module: self._run_module(m, result),
                max_retries=self.config.general.retries,
            )
            await scheduler.submit(task)

        await scheduler.run_all()

        for module in other_modules:
            task = Task(
                priority=int(Priority.NORMAL),
                name=module.name,
                coro_factory=lambda m=module: self._run_module(m, result),
                max_retries=self.config.general.retries,
            )
            await scheduler.submit(task)

        await scheduler.run_all()
        await scheduler.stop()

        result.finished_at = time.time()
        result.errors = scheduler.errors
        result.stats = {
            "modules_run": len(modules),
            "modules_with_errors": len(scheduler.errors),
            "duration_seconds": round(result.duration, 2),
        }

        await self._emit({"event": "scan_finished", "stats": result.stats})
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_modules(self) -> List[Any]:
        """Discover and instantiate all enabled scan modules.

        Returns:
            List of module instances ready for execution.
        """
        import godrecon.modules as modules_pkg

        enabled_modules = []
        modules_config = self.config.modules.model_dump()

        for importer, modname, ispkg in pkgutil.iter_modules(modules_pkg.__path__):
            if not ispkg:
                continue
            module_enabled = modules_config.get(modname, True)
            if not module_enabled:
                logger.debug("Module '%s' is disabled — skipping.", modname)
                continue

            try:
                pkg = importlib.import_module(f"godrecon.modules.{modname}")
                # Look for a class named after the module (CamelCase) or
                # fall back to any BaseModule subclass exported by the package.
                module_instance = self._instantiate_module(pkg, modname)
                if module_instance is not None:
                    enabled_modules.append(module_instance)
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not load module '%s': %s", modname, exc)

        return enabled_modules

    @staticmethod
    def _instantiate_module(pkg: Any, modname: str) -> Optional[Any]:
        """Try to instantiate a module from its package.

        Looks for a sub-module called ``runner`` or the first exported class
        that is a subclass of :class:`~godrecon.modules.base.BaseModule`.

        Args:
            pkg: The already-imported package object.
            modname: Module directory name (e.g. ``"subdomains"``).

        Returns:
            Module instance or ``None`` if no runnable class was found.
        """
        from godrecon.modules.base import BaseModule

        # Try loading a dedicated runner sub-module first
        for sub in ("runner", "aggregator", "probe", "scanner"):
            try:
                sub_mod = importlib.import_module(f"{pkg.__name__}.{sub}")
                for attr in vars(sub_mod).values():
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule
                    ):
                        return attr()
            except ModuleNotFoundError:
                pass
            except Exception:  # noqa: BLE001
                pass

        # Fallback: scan the package's own namespace
        for attr in vars(pkg).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
            ):
                return attr()

        return None

    async def _run_module(self, module: Any, result: ScanResult) -> None:
        """Execute a single module and store its result.

        Args:
            module: Module instance (must implement ``BaseModule``).
            result: The scan result object to populate.
        """
        await self._emit({"event": "module_started", "module": module.name})
        try:
            module_result = await module.run(self.target, self.config)
            result.module_results[module.name] = module_result
            await self._emit(
                {
                    "event": "module_finished",
                    "module": module.name,
                    "findings": len(module_result.findings) if module_result else 0,
                }
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Module '%s' failed: %s", module.name, exc)
            await self._emit(
                {"event": "module_error", "module": module.name, "error": str(exc)}
            )
            raise

    async def _emit(self, event: Dict[str, Any]) -> None:
        """Fire *event* to all registered event handlers.

        Args:
            event: Dictionary describing the event.
        """
        for handler in self._event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception:  # noqa: BLE001
                pass
