from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from guardian.schemas import CategoryRunSummary, FlowInventory, ScenarioResult


def _run_status(
    *,
    execute_enabled: bool,
    static_candidates: int,
    executed: int,
    observed: int,
) -> str:
    if static_candidates == 0:
        return "not_tested_no_static_candidates"
    if not execute_enabled:
        return "static_candidates_not_executed"
    if executed == 0:
        return "not_tested_no_execution"
    if observed > 0:
        return "tested_vulnerability_observed"
    return "tested_no_vulnerability_observed"


def build_report(
    run_id: str,
    inventory: FlowInventory,
    summaries: list[CategoryRunSummary],
    results: list[ScenarioResult],
    execute_enabled: bool,
) -> dict[str, Any]:
    observed = [
        result
        for result in results
        if result.runtime_assessment is not None
        and result.runtime_assessment.vulnerability_observed
    ]
    severity_counts = Counter(
        result.runtime_assessment.severity
        for result in observed
        if result.runtime_assessment is not None
    )

    by_category: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "static_candidates": 0,
            "executed": 0,
            "observed": 0,
            "scenario_ids": [],
        }
    )
    for result in results:
        bucket = by_category[result.scenario.category]
        bucket["static_candidates"] += 1
        bucket["scenario_ids"].append(result.scenario.id)
        if result.execution is not None:
            bucket["executed"] += 1
        if (
            result.runtime_assessment
            and result.runtime_assessment.vulnerability_observed
        ):
            bucket["observed"] += 1

    generation_calls = sum(item.generation_calls for item in summaries)
    duplicate_generations = sum(item.duplicate_generations for item in summaries)
    unique_scenarios = sum(item.unique_scenarios for item in summaries)
    grounded_candidates = sum(item.grounded_candidates for item in summaries)
    static_candidates = len(results)
    executed = sum(1 for result in results if result.execution is not None)
    observed_count = len(observed)

    result_rows = []
    readable_findings = []
    for result in results:
        if result.execution is None:
            status = "static_candidate_not_executed"
        elif result.runtime_assessment is None:
            status = "executed_inconclusive"
        elif result.runtime_assessment.vulnerability_observed:
            status = "tested_vulnerability_observed"
        else:
            status = "tested_control_held_or_not_observed"

        row = result.model_dump(mode="json")
        row["status"] = status
        result_rows.append(row)
        readable_findings.append(_readable_finding(row, status))

    return {
        "run_id": run_id,
        "execute_enabled": execute_enabled,
        "status": _run_status(
            execute_enabled=execute_enabled,
            static_candidates=static_candidates,
            executed=executed,
            observed=observed_count,
        ),
        "flow": {
            "id": inventory.flow_id,
            "name": inventory.flow_name,
            "description": inventory.flow_description,
            "agent_count": len(inventory.agent_ids),
            "tool_count": len(inventory.tool_ids),
            "component_count": len(inventory.components),
        },
        "summary": {
            "categories": len(summaries),
            "generation_calls": generation_calls,
            "duplicate_generations": duplicate_generations,
            "unique_scenarios": unique_scenarios,
            "grounded_candidates": grounded_candidates,
            "static_candidates": static_candidates,
            "executed": executed,
            "vulnerabilities_observed": observed_count,
            "severity_counts": dict(severity_counts),
        },
        "category_summaries": [
            item.model_dump(mode="json")
            for item in summaries
        ],
        "by_category": dict(by_category),
        "results": result_rows,
        "readable_findings": readable_findings,
    }


def _readable_finding(row: dict[str, Any], status: str) -> dict[str, Any]:
    """Flatten one scenario result into the same "what happened" shape shown
    in the markdown report, so the JSON download is just as legible."""
    scenario = row["scenario"]
    runtime = row.get("runtime_assessment") or {}
    execution = row.get("execution") or {}
    turns = execution.get("turns") or []
    replies = [(t.get("output_text") or t.get("error") or "").strip() for t in turns]
    replies = [r if len(r) <= 400 else r[:400] + "…" for r in replies if r]

    return {
        "scenario_id": scenario["id"],
        "title": scenario["title"],
        "category": scenario["category"],
        "status": status,
        "executed": bool(execution),
        "attack_objective": scenario.get("objective") or None,
        "targeted_tools": scenario.get("required_tools") or [],
        "what_was_sent": [
            (t.get("content", "") if isinstance(t, dict) else str(t))
            for t in (scenario.get("conversation") or [])
        ],
        "what_the_workflow_replied": replies,
        "vulnerability_observed": runtime.get("vulnerability_observed"),
        "severity": runtime.get("severity"),
        "confidence": runtime.get("confidence"),
        "evidence": runtime.get("evidence") or [],
        "why_it_held": runtime.get("controls_that_worked") or [],
        "recommended_fixes": runtime.get("recommended_fixes") or [],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    flow = report["flow"]

    lines = [
        f"# GuardianAI evaluation report — `{report['run_id']}`",
        "",
        "## Run status",
        "",
        f"**{report.get('status', 'unknown')}**",
        "",
    ]

    status = report.get("status")
    if status == "not_tested_no_static_candidates":
        lines.append(
            "No scenario reached the static-candidate stage. This result does not establish that the workflow is safe."
        )
    elif status == "static_candidates_not_executed":
        lines.append(
            "Static candidates were produced, but execution was disabled. No runtime vulnerability claim can be made."
        )
    elif status == "tested_no_vulnerability_observed":
        lines.append(
            "Scenarios were executed and no prohibited behavior was observed in this run."
        )
    elif status == "tested_vulnerability_observed":
        lines.append(
            "At least one executed scenario produced evidence of prohibited behavior."
        )

    lines.extend(
        [
            "",
            "## Run summary",
            "",
            f"- **Flow:** {flow.get('name') or flow.get('id')} (`{flow.get('id')}`)",
            f"- **Components:** {flow.get('component_count', 0)}",
            f"- **Agents detected:** {flow.get('agent_count', 0)}",
            f"- **Concrete tool actions detected:** {flow.get('tool_count', 0)}",
            f"- **Generation calls:** {summary.get('generation_calls', 0)}",
            f"- **Duplicate generations:** {summary.get('duplicate_generations', 0)}",
            f"- **Unique scenarios:** {summary.get('unique_scenarios', 0)}",
            f"- **Grounded candidates:** {summary.get('grounded_candidates', 0)}",
            f"- **Static candidates:** {summary.get('static_candidates', 0)}",
            f"- **Executed scenarios:** {summary.get('executed', 0)}",
            f"- **Observed vulnerabilities:** {summary.get('vulnerabilities_observed', 0)}",
            "",
            "## Category status",
            "",
            "| Category | Generated | Duplicates | Unique | Grounded | Static | Executed | Observed | Exhausted |",
            "|---|---:|---:|---:|---:|---:|---:|---:|:---:|",
        ]
    )

    for item in report.get("category_summaries", []):
        lines.append(
            f"| {item['category']} | {item.get('generation_calls', 0)} | "
            f"{item.get('duplicate_generations', 0)} | {item.get('unique_scenarios', item.get('attempts', 0))} | "
            f"{item.get('grounded_candidates', 0)} | {item.get('static_candidates', 0)} | "
            f"{item.get('executed', 0)} | {item.get('vulnerabilities_observed', 0)} | "
            f"{'Yes' if item.get('exhausted') else 'No'} |"
        )

    lines.extend(["", "## Scenario findings", ""])
    if not report.get("results"):
        lines.append("No scenario reached the static-candidate stage.")
        return "\n".join(lines) + "\n"

    for result in report["results"]:
        scenario = result["scenario"]
        runtime = result.get("runtime_assessment")
        execution = result.get("execution")
        lines.extend(
            [
                f"### {scenario['title']}",
                "",
                f"- **Scenario ID:** `{scenario['id']}`",
                f"- **Category:** `{scenario['category']}`",
                f"- **Status:** `{result.get('status', 'unknown')}`",
                f"- **Static plausibility:** {result['static_assessment']['plausible_vulnerability']}",
                f"- **Executed:** {'Yes' if execution else 'No'}",
            ]
        )

        if scenario.get("objective"):
            lines.append(f"- **Attack objective:** {scenario['objective']}")
        if scenario.get("required_tools"):
            lines.append(
                "- **Targeted tool(s):** " + ", ".join(scenario["required_tools"])
            )
        conversation = scenario.get("conversation") or []
        if conversation:
            lines.append("- **What was sent:**")
            for n, turn in enumerate(conversation, start=1):
                content = turn.get("content", "") if isinstance(turn, dict) else str(turn)
                lines.append(f"  {n}. {content}")

        turns = (execution or {}).get("turns") or []
        replies = [(t.get("output_text") or t.get("error") or "").strip() for t in turns]
        replies = [r for r in replies if r]
        if replies:
            lines.append("- **What the workflow replied:**")
            for n, out in enumerate(replies, start=1):
                preview = out if len(out) <= 400 else out[:400] + "…"
                lines.append(f"  {n}. {preview}")

        if runtime:
            lines.extend(
                [
                    f"- **Vulnerability observed:** {runtime['vulnerability_observed']}",
                    f"- **Severity:** {runtime['severity']}",
                    f"- **Confidence:** {runtime['confidence']}",
                ]
            )
            if runtime.get("evidence"):
                lines.append("- **Evidence:** " + "; ".join(runtime["evidence"]))
            if runtime.get("controls_that_worked"):
                lines.append(
                    "- **Why it held:** " + "; ".join(runtime["controls_that_worked"])
                )
            if runtime.get("recommended_fixes"):
                lines.append(
                    "- **Recommended fixes:** "
                    + "; ".join(runtime["recommended_fixes"])
                )
        lines.append("")

    return "\n".join(lines) + "\n"
