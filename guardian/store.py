from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class RunStore:
    def __init__(self, output_root: Path, run_id: str) -> None:
        self.run_id = run_id
        self.run_dir = output_root / run_id
        self.run_dir.mkdir(parents=True, exist_ok=False)

    @staticmethod
    def _jsonable(value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json")
        if isinstance(value, Path):
            return str(value)
        return value

    def write_json(self, name: str, value: Any) -> Path:
        path = self.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self._jsonable(value), ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
        return path

    def append_jsonl(self, name: str, value: Any) -> Path:
        path = self.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(self._jsonable(value), ensure_ascii=False, default=str) + "\n")
        return path

    def write_text(self, name: str, text: str) -> Path:
        path = self.run_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path
