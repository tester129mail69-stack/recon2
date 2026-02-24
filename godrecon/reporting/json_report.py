"""JSON export for GODRECON scan results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


class JSONReporter:
    """Serialise scan results to a JSON file."""

    def generate(self, results: Dict[str, Any], output_path: str) -> Path:
        """Write *results* as pretty-printed JSON to *output_path*.

        Args:
            results: Scan result dictionary.
            output_path: Destination file path.

        Returns:
            Path to the generated file.
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        return path
