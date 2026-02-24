"""Base module class for GODRECON scan modules.

All scan modules must inherit from :class:`BaseModule` and implement
``async def run(target, config) -> ModuleResult``.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from godrecon.core.config import Config
from godrecon.utils.logger import get_logger


@dataclass
class Finding:
    """A single finding discovered by a scan module.

    Attributes:
        title: Short title for the finding.
        description: Detailed description.
        severity: Severity level string (``info``, ``low``, ``medium``, ``high``, ``critical``).
        data: Arbitrary extra data associated with the finding.
        tags: List of classification tags.
    """

    title: str
    description: str = ""
    severity: str = "info"
    data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


@dataclass
class ModuleResult:
    """Container for the output of a single scan module.

    Attributes:
        module_name: Name of the producing module.
        target: Scan target.
        findings: List of :class:`Finding` objects.
        raw: Raw data dict for downstream consumption.
        duration: Time taken to run the module in seconds.
        error: Error message if the module failed.
    """

    module_name: str
    target: str
    findings: List[Finding] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    error: Optional[str] = None


class BaseModule(ABC):
    """Abstract base class for all GODRECON scan modules.

    Every module must declare metadata and implement :meth:`run`.

    Example::

        class MyModule(BaseModule):
            name = "my_module"
            description = "Does something cool"
            version = "1.0.0"
            category = "recon"

            async def _execute(self, target, config):
                return ModuleResult(module_name=self.name, target=target)
    """

    name: str = "base"
    description: str = "Base module"
    author: str = "GODRECON Team"
    version: str = "0.1.0"
    category: str = "general"

    def __init__(self) -> None:
        self.logger = get_logger(f"module.{self.name}")

    async def run(self, target: str, config: Config) -> ModuleResult:
        """Public entry point — wraps :meth:`_execute` with timing and error handling.

        Args:
            target: Primary scan target (domain or IP string).
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` containing all findings.
        """
        start = time.time()
        try:
            result = await self._execute(target, config)
            result.duration = time.time() - start
            return result
        except Exception as exc:  # noqa: BLE001
            self.logger.error("Module '%s' error: %s", self.name, exc)
            return ModuleResult(
                module_name=self.name,
                target=target,
                duration=time.time() - start,
                error=str(exc),
            )

    @abstractmethod
    async def _execute(self, target: str, config: Config) -> ModuleResult:
        """Execute the module logic.

        Subclasses *must* override this method.

        Args:
            target: Primary scan target.
            config: Global scan configuration.

        Returns:
            :class:`ModuleResult` with findings and raw data.
        """

    def __repr__(self) -> str:
        return f"<Module {self.name} v{self.version}>"
