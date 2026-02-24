"""Rich-based logging system for GODRECON.

Provides colourised, module-tagged log messages with optional file output.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)
_file_handler: Optional[logging.FileHandler] = None
_root_configured = False


def configure_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    verbose: bool = False,
) -> None:
    """Configure the root logger used by all GODRECON components.

    Args:
        level: Base log level (e.g. ``logging.DEBUG``).
        log_file: Optional filesystem path for a persistent log file.
        verbose: When ``True``, forces ``DEBUG`` level.
    """
    global _file_handler, _root_configured

    if verbose:
        level = logging.DEBUG

    root = logging.getLogger("godrecon")
    root.setLevel(level)
    root.handlers.clear()

    rich_handler = RichHandler(
        console=_console,
        rich_tracebacks=True,
        show_time=True,
        show_level=True,
        show_path=False,
        markup=True,
    )
    rich_handler.setLevel(level)
    root.addHandler(rich_handler)

    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        _file_handler = logging.FileHandler(file_path, encoding="utf-8")
        _file_handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        _file_handler.setFormatter(formatter)
        root.addHandler(_file_handler)

    _root_configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger under the ``godrecon`` hierarchy.

    Automatically configures the root logger on first use if it hasn't been
    configured yet.

    Args:
        name: Logger name, typically ``__name__`` of the calling module.

    Returns:
        :class:`logging.Logger` instance.
    """
    if not _root_configured:
        configure_logging()

    if name.startswith("godrecon.") or name == "godrecon":
        return logging.getLogger(name)
    return logging.getLogger(f"godrecon.{name}")
