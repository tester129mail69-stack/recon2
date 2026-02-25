"""Plugin SDK — utilities for creating custom GODRECON modules."""
from __future__ import annotations

import re
from pathlib import Path


def create_module_scaffold(
    module_name: str,
    output_dir: str,
    category: str = "custom",
    author: str = "Community",
) -> str:
    """Create a new module directory structure under *output_dir*.

    Creates:

    .. code-block:: text

        {output_dir}/{module_name}/
        ├── __init__.py
        └── scanner.py

    Args:
        module_name: Lowercase, alphanumeric + underscores module name.
        output_dir: Directory where the module folder will be created.
        category: Module category label (default: ``"custom"``).
        author: Module author (default: ``"Community"``).

    Returns:
        The absolute path to the created module directory as a string.

    Raises:
        ValueError: If *module_name* contains invalid characters.
    """
    if not re.match(r"^[a-z][a-z0-9_]*$", module_name):
        raise ValueError(
            f"Invalid module name {module_name!r}. "
            "Must start with a lowercase letter and contain only lowercase "
            "letters, digits, and underscores."
        )

    camel_name = "".join(word.capitalize() for word in module_name.split("_"))

    module_dir = Path(output_dir) / module_name
    module_dir.mkdir(parents=True, exist_ok=True)

    init_content = f'"""GODRECON {module_name} module."""\n'
    (module_dir / "__init__.py").write_text(init_content, encoding="utf-8")

    scanner_content = f'''"""Custom GODRECON module: {module_name}."""
from __future__ import annotations

from godrecon.modules.base import BaseModule, Finding, ModuleResult
from godrecon.core.config import Config
from godrecon.utils.logger import get_logger

logger = get_logger(__name__)


class {camel_name}Module(BaseModule):
    name = "{module_name}"
    description = "Custom module: {module_name}"
    author = "{author}"
    version = "0.1.0"
    category = "{category}"

    async def _execute(self, target: str, config: Config) -> ModuleResult:
        findings = []
        # TODO: Implement your reconnaissance logic here
        # Example:
        # findings.append(Finding(
        #     title="Example finding",
        #     severity="info",
        #     data={{"key": "value"}},
        # ))
        return ModuleResult(
            module_name=self.name,
            target=target,
            findings=findings,
        )
'''
    (module_dir / "scanner.py").write_text(scanner_content, encoding="utf-8")

    return str(module_dir)
