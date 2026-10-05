from __future__ import annotations

import json
import uuid
from typing import Any

from guardian.clients.llm import GuardianModelClient, _json_object_candidates
from guardian.config import CategoryConfig
from guardian.prompts import planner_messages
from guardian.schemas import Scenario


def _as_text(value: Any) -> str:
    """The trained model's `payload` is the literal string sent to Langflow.

    Older checkpoints occasionally emit it as an object
    ({"Body": "...", "Recipient": "..."}); flatten to the longest string,
    which is invariably the body carrying the attack.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        strings = [v for v in value.values() if isinstance(v, str) and v.strip()]
        if strings:
            return max(strings, key=len)
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        parts = [_as_text(v) for v in value if v]
        return "\n".join(p for p in parts if p)
    return str(value) if value is not None else ""


def _looks_like_scenario(obj: dict[str, Any]) -> bool:
    """A T2 scenario names an attack: it has a payload / entry point / grounding."""
    keys = set(obj.keys())
    return bool(keys & {"payload", "entry_point", "target_agent", "grounding",
                        "expected_violation", "conversation", "scenario"})


def translate_to_scenario(obj: dict[str, Any], category_id: str) -> dict[str, Any]:
    """Map the fine-tuned model's T2 output onto the demo's Scenario shape.

    The model was trained to emit
        {category, title, entry_point, target_agent, payload,
         expected_violation, steps[], grounding{tools,agents,fields}, reasoning}
    The demo executor consumes
        {category, title, objective, conversation[], required_tools, ...}

    The key bridges: `payload` is the user turn sent to Langflow, and
    `grounding.tools` (or the tools named in `steps`) are the required tools.
    """
    if "scenario" in obj and isinstance(obj["scenario"], dict):
        obj = {**obj, **obj["scenario"]}

    payload = _as_text(obj.get("payload") or obj.get("action") or "")
    setup_turn = _as_text(obj.get("setup_turn") or "")

    conversation = obj.get("conversation")
    turns: list[dict[str, str]] = []
    if isinstance(conversation, list) and conversation:
        for turn in conversation:
            if isinstance(turn, str):
                turns.append({"role": "user", "content": turn})
            elif isinstance(turn, dict) and turn.get("content"):
                turns.append({"role": "user", "content": _as_text(turn["content"])})
    if not turns:
        if setup_turn and setup_turn.strip() and setup_turn.strip() != payload.strip():
            turns.append({"role": "user", "content": setup_turn})
        if payload:
            turns.append({"role": "user", "content": payload})
    if not turns:
        turns = [{"role": "user",
                  "content": _as_text(obj.get("expected_violation")
                                      or obj.get("title") or "test message")}]

    grounding = obj.get("grounding") if isinstance(obj.get("grounding"), dict) else {}
    tools = list(grounding.get("tools") or [])
    if not tools:
        for step in obj.get("steps") or []:
            if isinstance(step, dict) and step.get("tool"):
                tools.append(step["tool"])

    violation = _as_text(obj.get("expected_violation") or obj.get("expected_result") or "")
    title = _as_text(obj.get("title") or f"{category_id} scenario")
    reasoning = obj.get("reasoning")
    assumptions = ([_as_text(r) for r in reasoning] if isinstance(reasoning, list)
                   else [_as_text(reasoning)] if reasoning else [])

    return {
        "category": category_id,
        "title": title if len(title) >= 3 else f"{category_id} scenario",
        "objective": violation or title or f"Attempt {category_id}",
        "conversation": turns,
        "required_tools": tools,
        "preconditions": [],
        "expected_safe_behavior": [],
        "prohibited_outcomes": [violation] if violation else [],
        "evidence_needed": [violation] if violation else [],
        "assumptions": assumptions,
        "severity_if_successful": "high",
    }


class ScenarioPlanner:
    """Generates a scenario and adapts the fine-tuned model's native output.

    The model is fixed (fine-tuned to emit the T2 format), so the demo speaks
    the model's language rather than the reverse: we ask for the trained format
    and translate it into the demo's Scenario at this boundary. Everything
    downstream — grounding, execution, reporting — keeps working unchanged.
    """

    def __init__(self, model: GuardianModelClient) -> None:
        self.model = model

    def create(
        self,
        category: CategoryConfig,
        setup_context: dict,
        prior_scenarios: list[dict],
        feedback: list[str],
    ) -> Scenario:
        text = self.model.chat(
            planner_messages(category, setup_context, prior_scenarios, feedback)
        )

        candidates = _json_object_candidates(text)

        def score(c: dict) -> tuple:
            has_payload = bool(str(c.get("payload") or "").strip())
            has_conv = bool(c.get("conversation"))
            has_anchor = bool(c.get("entry_point") or c.get("target_agent"))
            return (has_payload or has_conv, has_anchor, len(c))

        scored = [c for c in candidates if _looks_like_scenario(c)]
        chosen = max(scored, key=score) if scored else (
            candidates[-1] if candidates else None)
        if chosen is None:
            raise ValueError(
                f"Model returned no JSON object for {category.id}: {text[:400]}"
            )

        scenario = Scenario(**translate_to_scenario(chosen, category.id))
        scenario.category = category.id
        if not scenario.id:
            scenario.id = f"scn-{category.id}-{uuid.uuid4().hex[:10]}"
        return scenario
