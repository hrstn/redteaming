from __future__ import annotations

import json
from pathlib import Path

from ..findings import ScanResult


def write(result: ScanResult, output_path: str) -> None:
    data = result.to_dict()
    path = Path(output_path)
    path.write_text(json.dumps(data, indent=2, default=str))
