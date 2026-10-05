from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import yaml

SECRET_KEY_PATTERN = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|credential|authorization|private[_-]?key)",
    re.IGNORECASE,
)


def redact_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if SECRET_KEY_PATTERN.search(str(key)):
                result[str(key)] = "<redacted>"
            else:
                result[str(key)] = redact_secrets(item)
        return result
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return [redact_secrets(item) for item in value]
    return value


def load_data_file(path: Path) -> Any:
    suffix = path.suffix.lower()
    if suffix == ".json":
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    if suffix in {".yaml", ".yml"}:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle)
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    if suffix == ".jsonl":
        rows: list[Any] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    rows.append(json.loads(line))
        return rows
    return path.read_text(encoding="utf-8")


def truncate_json(value: Any, max_chars: int) -> Any:
    redacted = redact_secrets(value)
    rendered = json.dumps(redacted, ensure_ascii=False, default=str)
    if len(rendered) <= max_chars:
        return redacted
    return {
        "truncated": True,
        "original_characters": len(rendered),
        "content_preview": rendered[:max_chars],
    }


def extract_json_object(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    try:
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object")
        return parsed
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    raise ValueError("No valid JSON object found in model response")


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _scenario_payload(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        raw = value.model_dump(mode="json")
    elif isinstance(value, dict):
        raw = value
    else:
        raise TypeError("scenario_fingerprint expects a Scenario or dictionary")

    conversation: list[str] = []
    for item in raw.get("conversation", []) or []:
        if isinstance(item, dict):
            conversation.append(str(item.get("content", "")).strip())
        else:
            conversation.append(str(item).strip())

    return {
        "category": str(raw.get("category", "")).strip().lower(),
        "conversation": conversation,
        "required_tools": sorted(
            normalize_name(str(item))
            for item in raw.get("required_tools", []) or []
        ),
    }


def scenario_fingerprint(scenario: Any) -> str:
    """Fingerprint all material scenario fields, not just title and chat text."""

    rendered = json.dumps(
        _scenario_payload(scenario),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()[:20]


def collect_named_values(value: Any, keys: set[str]) -> set[str]:
    output: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in keys:
                if isinstance(item, str):
                    output.add(item)
                elif isinstance(item, list):
                    output.update(
                        str(v)
                        for v in item
                        if isinstance(v, (str, int, float))
                    )
            output.update(collect_named_values(item, keys))
    elif isinstance(value, list):
        for item in value:
            output.update(collect_named_values(item, keys))
    return output
