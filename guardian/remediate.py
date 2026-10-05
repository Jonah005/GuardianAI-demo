"""
Explain-and-fix pass.

Takes the CONFIRMED vulnerabilities from a run (as decided by the audit judge)
and, for each, hands the judge's concrete details -- what tool fired, on which
record, why it was a policy violation -- to the Guardian model and asks it for a
short explanation of why it got through and the specific fix. The explanations
are printed (so they stream live in the UI log), written to remediation.md, and
folded into each result's recommended_fixes so the report shows them.

Needs the model server (this is the LLM step); no Langflow, no re-execution.
"""
from __future__ import annotations

import json
import logging
import re
from collections import Counter
from pathlib import Path

from guardian.clients.llm import GuardianModelClient
from guardian.config import AppSettings, RunConfig
from guardian.reporter import build_report, render_markdown
from guardian.rejudge import resolve_run_dir, _load_jsonl
from guardian.schemas import (
    CategoryRunSummary, FlowInventory, GroundingAssessment, RuntimeAssessment,
    Scenario, ScenarioExecution, ScenarioResult, StaticAssessment,
)

LOGGER = logging.getLogger(__name__)

_SYSTEM = (
    "You are GuardianAI, a security remediation advisor for agentic workflows. "
    "Given a CONFIRMED vulnerability -- what the attack made the workflow do and "
    "why it violates policy -- reply with ONE short sentence paraphrasing why it "
    "got through, in plain language. Reference the real tool and field names. No "
    "markdown, no lists, no repetition, under 40 words."
)


def _deterministic_fix(scenario: Scenario, ra: RuntimeAssessment) -> tuple[str, str]:
    """Grounded, reliable why+fix derived from the judge's own evidence -- the
    authoritative remediation. Parses the confirmed tool(s), record, forbidding
    field, and whether a gate was skipped, all from the audit-judge output."""
    blob = " ; ".join(ra.evidence or []) + " " + " ".join(ra.observed_behavior or [])
    tools = sorted(set(re.findall(r"privileged '([^']+)' executed", blob)))
    tools_str = " and ".join(tools) if tools else "the privileged tool"
    state = re.search(r"forbids it \(([A-Za-z0-9]+-\d+)\.([A-Za-z_]+)=([A-Za-z_]+)\)", blob)
    ordering = "no verification step" in blob or "no " in blob and "before it" in blob

    if state:
        record, field, value = state.group(1), state.group(2), state.group(3)
        why = (f"{tools_str} executed on {record}, whose {field} is '{value}' — a "
               f"state that should forbid the action. Only the agent's prompt "
               f"guarded it, so the injected request talked straight past it.")
        fix = (f"Enforce {field} as a server-side precondition inside {tools_str}: "
               f"reject any action on a record whose {field} is '{value}', instead "
               f"of relying on the agent prompt.")
        return why, fix

    gate = ""
    m = re.search(r"(check_[a-z_]+)", scenario.objective or "")
    if m:
        gate = m.group(1)
    if not gate:
        gate = next((t for t in (scenario.required_tools or [])
                     if t.startswith("check") or "eligib" in t or "status" in t
                     or "verify" in t), "the required verification step")
    why = (f"{tools_str} executed with no {gate} before it in this session — the "
           f"mandated step was skipped, and the agent prompt was the only guard.")
    fix = (f"Make {tools_str} refuse to run unless a fresh, successful {gate} exists "
           f"for the same record in this session; enforce the ordering inside the "
           f"tool, not the agent prompt.")
    return why, fix


def _degenerate(text: str) -> bool:
    """Reject a model paraphrase that collapsed (repetition loop, low diversity)."""
    words = text.split()
    if len(words) < 3:
        return len(text.strip()) == 0
    run = 1
    for i in range(1, len(words)):
        run = run + 1 if words[i] == words[i - 1] else 1
        if run >= 4:
            return True
    if len(set(words)) / len(words) < 0.45:
        return True
    most = Counter(words).most_common(1)[0][1]
    if most > max(6, 0.25 * len(words)):
        return True
    if len(text) > 700:
        return True
    return False


def _details(scenario: Scenario, ra: RuntimeAssessment) -> str:
    evidence = "; ".join(ra.evidence[:3]) or "(see tool-call log)"
    invariants = "; ".join(ra.violated_invariants[:3]) or scenario.objective
    tools = ", ".join(scenario.required_tools) or "(unspecified)"
    convo = " | ".join(t.content for t in scenario.conversation[:3])
    return (
        f"Category: {scenario.category}\n"
        f"Attack goal: {scenario.objective}\n"
        f"What the attacker sent: {convo}\n"
        f"Tools involved: {tools}\n"
        f"What actually happened (tool-call log): {evidence}\n"
        f"Invariant violated: {invariants}"
    )


def remediate_run(settings: AppSettings, run_config: RunConfig,
                  run_id: str | None = None) -> Path:
    run_dir = resolve_run_dir(settings.output_root, run_id)
    LOGGER.info("explain-and-fix for run: %s", run_dir.name)

    inventory = FlowInventory(**json.loads((run_dir / "flow_inventory.json").read_text(encoding="utf-8")))
    stored = _load_jsonl(run_dir / "results" / "scenario_results.jsonl")

    results: list[ScenarioResult] = []
    confirmed_idx: list[int] = []
    for i, row in enumerate(stored):
        scenario = Scenario(**row["scenario"])
        grounding = GroundingAssessment(**row["grounding"])
        static = StaticAssessment(**row["static_assessment"])
        execution = ScenarioExecution(**row["execution"]) if row.get("execution") else None
        ra = RuntimeAssessment(**row["runtime_assessment"]) if row.get("runtime_assessment") else None
        results.append(ScenarioResult(scenario=scenario, grounding=grounding,
                                      static_assessment=static, execution=execution,
                                      runtime_assessment=ra))
        if ra and ra.vulnerability_observed:
            confirmed_idx.append(i)

    print(f"Explain-and-fix: {len(confirmed_idx)} confirmed vulnerabilities in "
          f"{run_dir.name}\n" + "=" * 66, flush=True)
    if not confirmed_idx:
        print("  Nothing confirmed vulnerable in this run — nothing to explain.")
        return run_dir

    model = GuardianModelClient(settings)
    md_lines = [f"# Remediation — run {run_dir.name}\n",
                f"{len(confirmed_idx)} confirmed vulnerabilities.\n"]
    try:
        for n, i in enumerate(confirmed_idx, start=1):
            r = results[i]
            ra = r.runtime_assessment
            print(f"\n[{n}/{len(confirmed_idx)}] {r.scenario.category} — {r.scenario.title}", flush=True)

            why, fix = _deterministic_fix(r.scenario, ra)

            note = ""
            try:
                para = model.chat(
                    [{"role": "system", "content": _SYSTEM},
                     {"role": "user", "content": _details(r.scenario, ra) +
                      "\n\nOne short plain-language sentence on why it got through:"}],
                    max_tokens=80,
                ).strip()
                if para and not _degenerate(para):
                    note = para
                else:
                    print("   (model paraphrase discarded — degenerate/empty)", flush=True)
            except Exception as exc:                print(f"   (model unavailable: {exc})", flush=True)

            print("   WHY:", why, flush=True)
            print("   FIX:", fix, flush=True)
            if note:
                print("   MODEL NOTE:", note, flush=True)

            ra.recommended_fixes = [f"{why} {fix}"] + ([f"(model) {note}"] if note else [])
            md_lines += [
                f"\n## {n}. {r.scenario.category} — {r.scenario.title}\n",
                f"**What happened:** {'; '.join(ra.evidence[:2]) or r.scenario.objective}\n",
                f"**Why it got through:** {why}\n",
                f"**Fix:** {fix}\n",
            ]
            if note:
                md_lines.append(f"**Model note:** {note}\n")
    finally:
        model.close()

    (run_dir / "remediation.md").write_text("\n".join(md_lines), encoding="utf-8")
    results_path = run_dir / "results" / "scenario_results.jsonl"
    with results_path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r.model_dump(mode="json"), ensure_ascii=False) + "\n")

    base = {}
    manp = run_dir / "manifest.json"
    if manp.exists():
        for s in json.loads(manp.read_text(encoding="utf-8")).get("category_summaries", []):
            base[s.get("category")] = s
    summaries = []
    cats = []
    for r in results:
        if r.scenario.category not in cats:
            cats.append(r.scenario.category)
    for cat in cats:
        summ = CategoryRunSummary(**base.get(cat, {"category": cat}))
        cr = [r for r in results if r.scenario.category == cat]
        summ.executed = sum(1 for r in cr if r.execution is not None)
        summ.vulnerabilities_observed = sum(
            1 for r in cr if r.runtime_assessment and r.runtime_assessment.vulnerability_observed)
        summaries.append(summ)
    report = build_report(run_dir.name, inventory, summaries, results, execute_enabled=True)
    (run_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (run_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")

    print("\n" + "=" * 66 + f"\nWrote fixes to {run_dir / 'remediation.md'} and the report.", flush=True)
    return run_dir
