from __future__ import annotations

import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import webbrowser
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, abort, jsonify, render_template, request, send_file


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = PROJECT_ROOT / "runs"
CONFIG_PATH = PROJECT_ROOT / "config" / "guardian.yaml"

BUSINESS_DB_PATH = Path(
    os.environ.get(
        "GUARDIAN_BUSINESS_DB",
        str(PROJECT_ROOT / "langflow_refund_database" / "langflow_refund_demo.db"),
    )
)


def _count_gate_interventions(since_iso: str | None) -> int | None:
    """How many real tool calls the enforcement gate blocked (REJECT/ESCALATE)
    since a run started. Read straight from the live workflow_audit table --
    a gate block is recorded there like any other tool response, so this is
    just counting real rows, not a separate tracked metric."""
    if not since_iso or not BUSINESS_DB_PATH.is_file():
        return None
    try:
        connection = sqlite3.connect(f"file:{BUSINESS_DB_PATH}?mode=ro", uri=True, timeout=2)
        try:
            row = connection.execute(
                """
                SELECT COUNT(*) FROM workflow_audit
                WHERE created_at >= ?
                  AND response_json LIKE '%"blocked": true%'
                """,
                (since_iso,),
            ).fetchone()
            return int(row[0]) if row else 0
        finally:
            connection.close()
    except sqlite3.Error:
        return None

app = Flask(__name__)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class RunManager:
    """Own one Guardian child process and expose a thread-safe UI snapshot."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._process: subprocess.Popen[str] | None = None
        self._logs: deque[str] = deque(maxlen=2500)
        self._status = "idle"
        self._started_at: str | None = None
        self._finished_at: str | None = None
        self._exit_code: int | None = None
        self._run_id: str | None = None
        self._report: dict[str, Any] | None = None
        self._error: str | None = None
        self._stop_requested = False
        self._report_floor = 0.0

    _MODEL_ENV = {
        "provider": "GUARDIAN_MODEL_PROVIDER",
        "api_key": "GUARDIAN_MODEL_API_KEY",
        "base_url": "GUARDIAN_MODEL_BASE_URL",
        "chat_path": "GUARDIAN_MODEL_CHAT_PATH",
        "model_name": "GUARDIAN_MODEL_NAME",
    }

    def start(self, model_overrides: dict[str, str] | None = None,
              mode: str = "run") -> tuple[bool, str]:
        with self._lock:
            if self._process is not None and self._process.poll() is None:
                return False, "A Guardian evaluation is already running."

            if not CONFIG_PATH.is_file():
                return False, f"Configuration file not found: {CONFIG_PATH}"

            self._logs.clear()
            self._status = "starting"
            self._started_at = _iso_now()
            self._finished_at = None
            self._exit_code = None
            self._run_id = None
            self._report = None
            self._error = None
            self._stop_requested = False
            self._report_floor = datetime.now(timezone.utc).timestamp()

            if mode == "rejudge":
                command = [
                    sys.executable, "-u", "-m", "guardian", "rejudge",
                    "--run", "latest",
                    "--config", str(CONFIG_PATH),
                    "--output-root", str(RUNS_ROOT), "--verbose",
                ]
            elif mode == "remediate":
                command = [
                    sys.executable, "-u", "-m", "guardian", "remediate",
                    "--run", "latest",
                    "--config", str(CONFIG_PATH),
                    "--output-root", str(RUNS_ROOT), "--verbose",
                ]
            else:
                command = [
                    sys.executable,
                    "-u",
                    "-m",
                    "guardian",
                    "run",
                    "--execute",
                    "--confirm-side-effects",
                    "--config",
                    str(CONFIG_PATH),
                    "--output-root",
                    str(RUNS_ROOT),
                    "--verbose",
                ]
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            for key, value in (model_overrides or {}).items():
                env_name = self._MODEL_ENV.get(key)
                if env_name and value:
                    env[env_name] = str(value)
            chosen = (model_overrides or {}).get("model_name") or "default (.env)"
            self._append_log(f"Guardian model for this run: {chosen}")
            creation_flags = 0
            if os.name == "nt":
                creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP

            try:
                self._process = subprocess.Popen(
                    command,
                    cwd=PROJECT_ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    creationflags=creation_flags,
                )
            except Exception as exc:
                self._status = "failed"
                self._finished_at = _iso_now()
                self._error = str(exc)
                return False, f"Could not start Guardian: {exc}"

            self._status = "running"
            msg = ("Re-judging the latest run (audit judge only)..." if mode == "rejudge"
                   else "Explaining fixes for the latest run's confirmed issues..." if mode == "remediate"
                   else "Guardian full evaluation started.")
            self._append_log(msg)
            threading.Thread(target=self._collect_output, daemon=True).start()
            return True, msg

    def stop(self) -> tuple[bool, str]:
        with self._lock:
            process = self._process
            if process is None or process.poll() is not None:
                return False, "No Guardian evaluation is running."
            self._stop_requested = True
            self._status = "stopping"
            self._append_log("Stop requested. Waiting for Guardian to exit...")

        try:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(signal.SIGTERM)
        except (OSError, ValueError):
            process.terminate()
        threading.Thread(target=self._force_stop, args=(process,), daemon=True).start()
        return True, "Stop requested."

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            summary = (self._report or {}).get("summary", {})
            categories = (self._report or {}).get("category_summaries", [])
            report_urls = None
            if self._run_id:
                report_urls = {
                    "markdown": f"/reports/{self._run_id}/report.md",
                    "json": f"/reports/{self._run_id}/report.json",
                }
            return {
                "status": self._status,
                "started_at": self._started_at,
                "finished_at": self._finished_at,
                "exit_code": self._exit_code,
                "run_id": self._run_id,
                "error": self._error,
                "logs": list(self._logs),
                "summary": summary,
                "categories": categories,
                "report_status": (self._report or {}).get("status"),
                "flow": (self._report or {}).get("flow", {}),
                "report_urls": report_urls,
                "gate_interventions": _count_gate_interventions(self._started_at),
            }

    def report_path(self, run_id: str, filename: str) -> Path:
        if filename not in {"report.md", "report.json"}:
            abort(404)
        candidate = (RUNS_ROOT / run_id / filename).resolve()
        try:
            candidate.relative_to(RUNS_ROOT.resolve())
        except ValueError:
            abort(404)
        if not candidate.is_file():
            abort(404)
        return candidate

    def _append_log(self, message: str) -> None:
        clean = message.rstrip("\r\n")
        if clean:
            self._logs.append(clean)

    def _collect_output(self) -> None:
        with self._lock:
            process = self._process
        if process is None:
            return

        assert process.stdout is not None
        for line in iter(process.stdout.readline, ""):
            with self._lock:
                self._append_log(line)
        process.stdout.close()
        exit_code = process.wait()

        with self._lock:
            self._exit_code = exit_code
            self._finished_at = _iso_now()
            self._load_latest_report()
            if self._stop_requested:
                self._status = "stopped"
                self._append_log("Guardian evaluation stopped.")
            elif exit_code == 0:
                self._status = "completed"
                self._append_log("Guardian full evaluation completed.")
            else:
                self._status = "failed"
                self._error = f"Guardian exited with code {exit_code}. Check the log for details."
                self._append_log(self._error)
            self._process = None

    def _load_latest_report(self) -> None:
        if not RUNS_ROOT.is_dir():
            return
        reports = [
            path
            for path in RUNS_ROOT.glob("*/report.json")
            if path.stat().st_mtime >= self._report_floor - 2
        ]
        if not reports:
            return
        latest = max(reports, key=lambda path: path.stat().st_mtime)
        try:
            report = json.loads(latest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            self._error = f"Run finished, but the report could not be read: {exc}"
            return
        self._report = report
        self._run_id = str(report.get("run_id") or latest.parent.name)

    def _force_stop(self, process: subprocess.Popen[str]) -> None:
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()


manager = RunManager()


@app.get("/")
def index() -> str:
    return render_template("index.html")


@app.get("/api/status")
def status():
    return jsonify(manager.snapshot())


_DEEPSEEK_DEFAULTS = {
    "base_url": "https://api.deepseek.com/v1",
    "chat_path": "/chat/completions",
    "model_name": "deepseek-chat",
}


@app.post("/api/run")
def start_run():
    body = request.get_json(silent=True) or {}
    overrides: dict[str, str] = {}
    provider = str(body.get("provider") or "local").strip().lower()
    if provider == "deepseek":
        overrides["provider"] = "deepseek"
        overrides["base_url"] = str(body.get("base_url") or _DEEPSEEK_DEFAULTS["base_url"])
        overrides["chat_path"] = str(body.get("chat_path") or _DEEPSEEK_DEFAULTS["chat_path"])
        overrides["model_name"] = str(body.get("model_name") or _DEEPSEEK_DEFAULTS["model_name"])
        overrides["api_key"] = str(body.get("api_key") or "")
        if not overrides["api_key"]:
            return jsonify({"ok": False,
                            "message": "DeepSeek selected but no API key was provided."}), 400
    started, message = manager.start(overrides)
    return jsonify({"ok": started, "message": message}), 202 if started else 409


@app.post("/api/rejudge")
def rejudge_run_route():
    started, message = manager.start(mode="rejudge")
    return jsonify({"ok": started, "message": message}), 202 if started else 409


@app.post("/api/remediate")
def remediate_run_route():
    started, message = manager.start(mode="remediate")
    return jsonify({"ok": started, "message": message}), 202 if started else 409


@app.post("/api/stop")
def stop_run():
    stopped, message = manager.stop()
    return jsonify({"ok": stopped, "message": message}), 202 if stopped else 409


def _latest_run_dir() -> Path | None:
    if not RUNS_ROOT.is_dir():
        return None
    runs = [p.parent.parent for p in RUNS_ROOT.glob("*/results/scenario_results.jsonl")]
    return max(runs, key=lambda p: p.stat().st_mtime) if runs else None


def _run_dir_for(run_id: str) -> Path | None:
    """Resolve a run_id to its directory, refusing to escape RUNS_ROOT."""
    if not RUNS_ROOT.is_dir():
        return None
    candidate = (RUNS_ROOT / run_id).resolve()
    try:
        candidate.relative_to(RUNS_ROOT.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_dir() else None


def _resolve_run_dir(run_id: str | None) -> Path | None:
    return _run_dir_for(run_id) if run_id else _latest_run_dir()


def _run_started_at(run_dir: Path) -> str | None:
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8")).get("created_at")
    except (OSError, json.JSONDecodeError):
        return None


def _list_runs() -> list[dict[str, Any]]:
    """Every past run that has a finished report, newest first -- read straight
    off disk so this works even with no Guardian process running (no Colab,
    no Langflow needed to just browse prior results)."""
    if not RUNS_ROOT.is_dir():
        return []
    entries: list[dict[str, Any]] = []
    for report_path in RUNS_ROOT.glob("*/report.json"):
        run_dir = report_path.parent
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        summary = report.get("summary", {}) or {}
        flow = report.get("flow", {}) or {}
        entries.append({
            "run_id": str(report.get("run_id") or run_dir.name),
            "flow_name": flow.get("name") or flow.get("id") or "Unnamed flow",
            "report_status": report.get("status"),
            "generated": summary.get("unique_scenarios"),
            "executed": summary.get("executed"),
            "vulnerabilities_observed": summary.get("vulnerabilities_observed", 0),
            "created_at": _run_started_at(run_dir),
            "_mtime": report_path.stat().st_mtime,
        })
    entries.sort(key=lambda item: item["_mtime"], reverse=True)
    for item in entries:
        del item["_mtime"]
    return entries


@app.get("/api/runs")
def list_runs():
    """List past runs for the 'view previous run' picker -- pure disk read,
    no subprocess, no Langflow/model connectivity required."""
    return jsonify({"runs": _list_runs()})


@app.get("/api/runs/<run_id>")
def run_detail(run_id: str):
    """Full snapshot of one past run, shaped exactly like /api/status so the
    same frontend render() can display it without a live run in progress."""
    run_dir = _run_dir_for(run_id)
    if run_dir is None:
        abort(404)
    report_file = run_dir / "report.json"
    if not report_file.is_file():
        abort(404)
    try:
        report = json.loads(report_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        abort(404)
    started_at = _run_started_at(run_dir)
    return jsonify({
        "status": "completed",
        "started_at": started_at,
        "finished_at": None,
        "exit_code": 0,
        "run_id": str(report.get("run_id") or run_dir.name),
        "error": None,
        "logs": [],
        "summary": report.get("summary", {}),
        "categories": report.get("category_summaries", []),
        "report_status": report.get("status"),
        "flow": report.get("flow", {}),
        "report_urls": {
            "markdown": f"/reports/{run_dir.name}/report.md",
            "json": f"/reports/{run_dir.name}/report.json",
        },
        "gate_interventions": _count_gate_interventions(started_at),
    })


def _remediation_items(run_dir: Path) -> list[dict]:
    items = []
    results_file = run_dir / "results" / "scenario_results.jsonl"
    try:
        for line in results_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            ra = r.get("runtime_assessment") or {}
            if ra.get("vulnerability_observed") and ra.get("recommended_fixes"):
                fixes = ra.get("recommended_fixes") or []
                note = " ".join(fixes[1:]).replace("(model) ", "", 1) if len(fixes) > 1 else ""
                items.append({
                    "category": r["scenario"].get("category", ""),
                    "title": r["scenario"].get("title", ""),
                    "what_happened": (ra.get("evidence") or [""])[0],
                    "fix": fixes[0] if fixes else "",
                    "note": note,
                })
    except (OSError, json.JSONDecodeError):
        pass
    return items


@app.get("/api/remediation")
def remediation():
    """Confirmed vulnerabilities of a run, with their fix explanations
    (populated by Explain & fix). Drives the on-screen remediation panel.
    Defaults to the latest run; pass ?run=<run_id> to view an older one."""
    run_dir = _resolve_run_dir(request.args.get("run"))
    if run_dir is None:
        return jsonify({"available": False, "items": []})
    items = _remediation_items(run_dir)
    return jsonify({"available": bool(items), "run_id": run_dir.name,
                    "count": len(items), "items": items})


def _all_readable_findings(run_dir: Path) -> list[dict]:
    """Every executed scenario in a run, in the flat 'what happened' shape --
    read straight from report.json's readable_findings (added alongside the
    fuller markdown/JSON report). Falls back to the confirmed-issues-only
    shape for older runs generated before that field existed."""
    report_file = run_dir / "report.json"
    try:
        report = json.loads(report_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _remediation_items(run_dir)
    findings = report.get("readable_findings")
    return findings if findings else _remediation_items(run_dir)


@app.get("/api/remediation.pdf")
def remediation_pdf():
    """Downloadable PDF covering every scenario the run executed -- what was
    attempted, what it targeted, what was sent, how the workflow responded,
    and the verdict -- not just the confirmed issues.
    ?run=<run_id>, default latest."""
    run_dir = _resolve_run_dir(request.args.get("run"))
    items = _all_readable_findings(run_dir) if run_dir else []
    from guardian.pdf_export import build_remediation_pdf
    run_id = run_dir.name if run_dir else "latest"
    pdf = build_remediation_pdf(items, run_id)
    from flask import Response
    return Response(pdf, mimetype="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="guardian_report_{run_id}.pdf"'})


@app.get("/reports/<run_id>/<filename>")
def report(run_id: str, filename: str):
    path = manager.report_path(run_id, filename)
    return send_file(path, as_attachment=filename.endswith(".json"))


def main() -> None:
    preferred_port = int(os.environ.get("GUARDIAN_UI_PORT", "5050"))
    port = preferred_port
    for candidate in range(preferred_port, preferred_port + 10):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", candidate))
            except OSError:
                continue
            port = candidate
            break
    else:
        raise RuntimeError(
            f"No available local port from {preferred_port} to {preferred_port + 9}."
        )

    url = f"http://127.0.0.1:{port}"
    if os.environ.get("GUARDIAN_UI_NO_BROWSER") != "1":
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
