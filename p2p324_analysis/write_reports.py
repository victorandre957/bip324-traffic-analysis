import csv
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class ReportWriter:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_json(self, name: str, data: Any) -> Path:
        path = self.output_dir / name
        path.write_text(json.dumps(self._jsonable(data), indent=2, sort_keys=True), encoding="utf-8")
        return path

    def write_csv(self, name: str, rows: list[Any], fieldnames: list[str] | None = None) -> Path:
        path = self.output_dir / name
        materialized = [self._jsonable(row) for row in rows]
        if not materialized and not fieldnames:
            path.write_text("", encoding="utf-8")
            return path
        resolved_fieldnames = fieldnames or sorted({key for row in materialized for key in row.keys()})
        with path.open("w", newline="", encoding="utf-8") as file_obj:
            writer = csv.DictWriter(file_obj, fieldnames=resolved_fieldnames, extrasaction="ignore")
            writer.writeheader()
            for row in materialized:
                writer.writerow(row)
        return path

    def _jsonable(self, data: Any) -> Any:
        if isinstance(data, BaseModel):
            return self._jsonable(data.model_dump(mode="json"))
        if isinstance(data, dict):
            return {str(key): self._jsonable(value) for key, value in data.items()}
        if isinstance(data, list):
            return [self._jsonable(item) for item in data]
        if isinstance(data, tuple):
            return list(data)
        if isinstance(data, bytes):
            return data.hex()
        return data
