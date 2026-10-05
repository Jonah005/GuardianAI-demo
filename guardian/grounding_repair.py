"""
Deterministic grounding-repair of record identifiers in a generated scenario.

Two jobs, both driven entirely by the connected environment's real data -- no
domain facts hardcoded:

  1. SUBSTITUTE phantom IDs. Any identifier-shaped token the model invented
     (e.g. REF-1001) that does NOT exist in the environment but shares an ID
     family with real records (real refunds are REF-3001..) is replaced by a
     real ID of that same family. Families (prefixes) are learned from the data.

  2. ENSURE the conversation carries a real ID. The model often puts the target
     ID only in the scenario's metadata, so the message the agent actually reads
     contains no record reference and the first agent can look nothing up. If the
     conversation is missing every real ID the scenario is about, the most-
     referenced one is woven into the opening turn so the request can actually
     enter the workflow.

If the environment exposes no record IDs (nothing to ground against), this is a
no-op and the scenario passes through unchanged.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from guardian.record_vocab import _ID_TOKEN, _prefix_of, real_id_index


def _build_id_mapping(
    text_blob: str,
    all_ids: set[str],
    groups: dict[str, list[str]],
) -> dict[str, str]:
    """Map each phantom ID token in the text to a real ID of the same family."""
    mapping: dict[str, str] = {}
    used: dict[str, set[str]] = {}
    for token in _ID_TOKEN.findall(text_blob):
        if token in all_ids or token in mapping:
            continue
        pfx = _prefix_of(token)
        if not pfx or pfx not in groups:
            continue
        candidates = groups[pfx]
        chosen_used = used.setdefault(pfx, set())
        pick = next((c for c in candidates if c not in chosen_used), candidates[0])
        chosen_used.add(pick)
        mapping[token] = pick
    return mapping


def _apply_mapping(value: Any, mapping: dict[str, str]) -> Any:
    """Recursively replace mapped tokens in every string within the structure."""
    if not mapping:
        return value
    if isinstance(value, str):
        out = value
        for phantom, real in mapping.items():
            out = re.sub(rf"\b{re.escape(phantom)}\b", real, out)
        return out
    if isinstance(value, list):
        return [_apply_mapping(v, mapping) for v in value]
    if isinstance(value, dict):
        return {k: _apply_mapping(v, mapping) for k, v in value.items()}
    return value


def _conversation_text(raw: dict[str, Any]) -> str:
    parts = []
    for turn in raw.get("conversation", []) or []:
        if isinstance(turn, dict):
            parts.append(str(turn.get("content", "")))
        else:
            parts.append(str(turn))
    return "\n".join(parts)


def _all_referenced_real_ids(raw: dict[str, Any], all_ids: set[str]) -> list[str]:
    blob = _serialise(raw)
    found = [t for t in _ID_TOKEN.findall(blob) if t in all_ids]
    return found


def _serialise(value: Any) -> str:
    import json
    return json.dumps(value, ensure_ascii=False, default=str)


def repair_scenario_dict(
    raw: dict[str, Any],
    vocab: dict[str, list[str]],
) -> tuple[dict[str, Any], list[str]]:
    """Repair a scenario given as a plain dict. Returns (repaired, change notes)."""
    changes: list[str] = []
    if not vocab:
        return raw, changes

    all_ids, groups = real_id_index(vocab)
    if not all_ids:
        return raw, changes

    blob = _serialise(raw)
    mapping = _build_id_mapping(blob, all_ids, groups)
    if mapping:
        raw = _apply_mapping(raw, mapping)
        changes.append(
            "Substituted phantom record IDs with real ones: "
            + ", ".join(f"{k}->{v}" for k, v in mapping.items())
        )

    referenced = _all_referenced_real_ids(raw, all_ids)
    conv_text = _conversation_text(raw)
    conv_has_real = any(rid in conv_text for rid in all_ids)
    if referenced and not conv_has_real:
        target = Counter(referenced).most_common(1)[0][0]
        conversation = raw.get("conversation") or []
        if conversation and isinstance(conversation[0], dict):
            first = conversation[0]
            first["content"] = (
                f"{str(first.get('content', '')).rstrip()} "
                f"(reference id: {target})"
            ).strip()
            changes.append(
                f"Injected real reference id '{target}' into the opening turn so "
                f"the request can enter the workflow."
            )
    return raw, changes


def repair_scenario(scenario: Any, vocab: dict[str, list[str]]) -> tuple[Any, list[str]]:
    """Repair a Scenario model. Returns (repaired_scenario, change notes).

    On any failure, returns the original scenario unchanged -- a grounding aid
    must never break the pipeline.
    """
    from guardian.schemas import Scenario
    try:
        raw = scenario.model_dump(mode="json")
        repaired_raw, changes = repair_scenario_dict(raw, vocab)
        if not changes:
            return scenario, changes
        return Scenario.model_validate(repaired_raw), changes
    except Exception:        return scenario, []
