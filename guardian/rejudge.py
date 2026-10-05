"""
Re-judge an existing run WITHOUT re-generating or re-executing.

Re-runs only the deterministic audit judge over the executions already stored in
a run, then rewrites results/scenario_results.jsonl, report.json and report.md.
Needs neither the model nor Langflow -- it reads the workflow's tool-call log
(which persists) and the run's saved transcripts, so it is fast and safe to run
repeatedly (e.g. after changing the judge logic).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from guardian.audit_judge import AuditJudge, merge_runtime_assessments
from guardian.config import AppSettings, RunConfig
from guardian.reporter import build_report, render_markdown
from guardian.schemas import (
    CategoryRunSummary, FlowInventory, GroundingAssessment, RuntimeAssessment,
    Scenario, ScenarioExecution, ScenarioResult, StaticAssessment,
)

LOGGER = logging.getLogger(__name__)


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def resolve_run_dir(output_root: Path, run_id: str | None) -> Path:
    output_root = Path(output_root)
    if run_id and run_id != "latest":
        d = output_root / run_id
        if not d.exists():
            raise FileNotFoundError(f"run not found: {d}")
        return d
    candidates = [p.parent.parent for p in output_root.glob("*/results/scenario_results.jsonl")]
    if not candidates:
        raise FileNotFoundError(f"no completed runs with results under {output_root}")
    return max(candidates, key=lambda p: p.stat().st_mtime)


def rejudge_run(settings: AppSettings, run_config: RunConfig,
                run_id: str | None = None) -> Path:
    run_dir = resolve_run_dir(settings.output_root, run_id)
    LOGGER.info("re-judging run: %s", run_dir.name)

    setup_context = json.loads((run_dir / "setup_context.json").read_text(encoding="utf-8")) \
        if (run_dir / "setup_context.json").exists() else {}
    inventory = FlowInventory(**json.loads((run_dir / "flow_inventory.json").read_text(encoding="utf-8")))

    stored = _load_jsonl(run_dir / "results" / "scenario_results.jsonl")
    if not stored:
        raise FileNotFoundError(f"no scenario_results.jsonl in {run_dir}")

    audit_judge = AuditJudge(settings.database_url)
    results: list[ScenarioResult] = []
    changed = 0

    for row in stored:
        scenario = Scenario(**row["scenario"])
        grounding = GroundingAssessment(**row["grounding"])
        static = StaticAssessment(**row["static_assessment"])
        execution = ScenarioExecution(**row["execution"]) if row.get("execution") else None

        old_ra = RuntimeAssessment(**row["runtime_assessment"]) if row.get("runtime_assessment") else None
        new_ra = old_ra
        if execution is not None:
            audit = None
            try:
                audit = audit_judge.verdict(scenario, execution, setup_context)
            except Exception:                LOGGER.exception("audit judge failed for %s", scenario.id)
            if audit is not None:
                new_ra = merge_runtime_assessments(audit, old_ra)
                new_ra.notes.append("Re-judged (audit judge re-run over stored execution).")
        if old_ra is None or (new_ra is not None and
                              new_ra.vulnerability_observed != (old_ra.vulnerability_observed if old_ra else None)):
            changed += 1

        results.append(ScenarioResult(scenario=scenario, grounding=grounding,
                                      static_assessment=static, execution=execution,
                                      runtime_assessment=new_ra))

    summaries: list[CategoryRunSummary] = []
    manifest_path = run_dir / "manifest.json"
    base_summaries = {}
    if manifest_path.exists():
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
        for s in man.get("category_summaries", []):
            base_summaries[s.get("category")] = s
    cats = []
    for r in results:
        if r.scenario.category not in cats:
            cats.append(r.scenario.category)
    for cat in cats:
        base = base_summaries.get(cat, {"category": cat})
        summ = CategoryRunSummary(**base)
        cat_results = [r for r in results if r.scenario.category == cat]
        summ.executed = sum(1 for r in cat_results if r.execution is not None)
        summ.vulnerabilities_observed = sum(
            1 for r in cat_results
            if r.runtime_assessment and r.runtime_assessment.vulnerability_observed)
        summaries.append(summ)

    results_path = run_dir / "results" / "scenario_results.jsonl"
    with results_path.open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r.model_dump(mode="json"), ensure_ascii=False) + "\n")

    report = build_report(run_dir.name, inventory, summaries, results, execute_enabled=True)
    (run_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    (run_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")

    total_vuln = sum(1 for r in results
                     if r.runtime_assessment and r.runtime_assessment.vulnerability_observed)
    LOGGER.info("re-judge complete: %d scenarios, %d now flagged vulnerable, %d verdicts changed",
                len(results), total_vuln, changed)
    print(f"Re-judged {run_dir.name}: {len(results)} scenarios | "
          f"{total_vuln} vulnerable | {changed} verdicts changed")
    return run_dir
