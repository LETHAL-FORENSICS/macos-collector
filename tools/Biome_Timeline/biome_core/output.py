"""
output.py - CSV and JSONL writers with stable, timeline-friendly schemas.

* CSV: ExtraFields is serialised to a compact JSON string (Timeline Explorer /
  Excel friendly). Booleans -> "True"/"False"/"" .
* JSONL: one JSON object per line; ExtraFields is a true nested object.
"""

from __future__ import annotations

import csv
import json
from typing import Dict, Iterable, List, Optional


def _csv_cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                          default=str)
    return str(value)


class CsvWriter:
    def __init__(self, path: str, columns: List[str]):
        self.columns = columns
        self._fh = open(path, "w", newline="", encoding="utf-8-sig")
        self._w = csv.DictWriter(
            self._fh, fieldnames=columns, extrasaction="ignore",
            quoting=csv.QUOTE_MINIMAL,
        )
        self._w.writeheader()

    def write(self, row: Dict):
        self._w.writerow({c: _csv_cell(row.get(c, "")) for c in self.columns})

    def close(self):
        self._fh.close()


class JsonlWriter:
    def __init__(self, path: str):
        self._fh = open(path, "w", encoding="utf-8")

    def write(self, row: Dict):
        # Keep ExtraFields as an object; coerce empty strings on bool col only.
        self._fh.write(json.dumps(row, ensure_ascii=False, default=str))
        self._fh.write("\n")

    def close(self):
        self._fh.close()


class JsonArrayWriter:
    """Optional single big JSON array (less preferred than JSONL)."""
    def __init__(self, path: str):
        self._path = path
        self._rows: List[Dict] = []

    def write(self, row: Dict):
        self._rows.append(row)

    def close(self):
        with open(self._path, "w", encoding="utf-8") as fh:
            json.dump(self._rows, fh, ensure_ascii=False, indent=2, default=str)
