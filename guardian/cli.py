from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from guardian.clients.langflow import LangflowClient
from guardian.clients.llm import GuardianModelClient
from guardian.config import AppSettings, load_run_config
from guardian.flow_inventory import extract_flow_inventory
from guardian.pipeline import GuardianPipeline

app = typer.Typer(no_args_is_help=True, help="GuardianAI local Langflow evaluation runner")
console = Console()


def _settings(config: Path | None = None, output_root: Path | None = None) -> AppSettings:
    settings = AppSettings()
    if config is not None:
        settings.config_path = config
    if output_root is not None:
        settings.output_root = output_root
    return settings


@app.command()
def doctor(config: Path | None = typer.Option(None, help="Path to guardian YAML config.")) -> None:
    """Check model and Langflow connectivity without executing a workflow scenario."""
    settings = _settings(config=config)
    missing = settings.validate_required()
    if missing:
        raise typer.BadParameter("Missing required environment variables: " + ", ".join(missing))
    run_config = load_run_config(settings.config_path)

    table = Table(title="Guardian connectivity check")
    table.add_column("Service")
    table.add_column("Status")
    table.add_column("Details")

    model = GuardianModelClient(settings)
    try:
        reply = model.chat(
            [
                {"role": "system", "content": "Return a minimal acknowledgement."},
                {"role": "user", "content": "Reply with OK."},
            ],
            max_tokens=32,
        )
        table.add_row("Guardian model", "OK", reply[:120])
    except Exception as exc:
        table.add_row("Guardian model", "FAILED", str(exc)[:300])
    finally:
        model.close()

    langflow = LangflowClient(settings, run_config.execution)
    try:
        flow = langflow.get_flow()
        table.add_row("Langflow", "OK", f"{flow.get('name', 'unnamed')} / {settings.langflow_flow_id}")
    except Exception as exc:
        table.add_row("Langflow", "FAILED", str(exc)[:300])
    finally:
        langflow.close()
    console.print(table)


@app.command("inspect-flow")
def inspect_flow(
    output: Path = typer.Option(Path("flow_inventory.json"), help="Where to save the redacted inventory."),
    config: Path | None = typer.Option(None, help="Path to guardian YAML config."),
) -> None:
    """Read the Langflow graph and extract agents, tools, components, and edges."""
    settings = _settings(config=config)
    run_config = load_run_config(settings.config_path)
    client = LangflowClient(settings, run_config.execution)
    try:
        flow = client.get_flow()
        inventory = extract_flow_inventory(flow, settings.langflow_flow_id)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(inventory.model_dump_json(indent=2), encoding="utf-8")
    finally:
        client.close()

    console.print(
        Panel.fit(
            f"Saved [bold]{output}[/bold]\n"
            f"Agents: {len(inventory.agent_ids)} | Tools: {len(inventory.tool_ids)} | Components: {len(inventory.components)}"
        )
    )


@app.command()
def run(
    execute: bool = typer.Option(False, "--execute", help="Execute accepted scenarios through Langflow."),
    confirm_side_effects: bool = typer.Option(
        False,
        "--confirm-side-effects",
        help="Confirm the connected Langflow flow points to a test environment where tool side effects are acceptable.",
    ),
    config: Path | None = typer.Option(None, help="Path to guardian YAML config."),
    output_root: Path | None = typer.Option(None, help="Directory for run artifacts."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Plan, ground, statically evaluate, optionally execute, and publish a report."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)
    settings = _settings(config=config, output_root=output_root)
    missing = settings.validate_required()
    if missing:
        raise typer.BadParameter("Missing required environment variables: " + ", ".join(missing))
    if execute and not (confirm_side_effects or settings.allow_side_effects):
        raise typer.BadParameter(
            "Execution is blocked until you pass --confirm-side-effects or set GUARDIAN_ALLOW_SIDE_EFFECTS=true."
        )

    run_config = load_run_config(settings.config_path)
    pipeline = GuardianPipeline(settings, run_config)
    try:
        run_dir = pipeline.run(execute=execute)
    finally:
        pipeline.close()
    console.print(Panel.fit(f"Guardian run complete.\nArtifacts: [bold]{run_dir}[/bold]"))


@app.command("rejudge")
def rejudge(
    run: str = typer.Option("latest", "--run", help="Run id to re-judge, or 'latest'."),
    config: Path | None = typer.Option(None, help="Path to guardian YAML config."),
    output_root: Path | None = typer.Option(None, help="Directory for run artifacts."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Re-run ONLY the audit judge over an existing run's executions and rewrite
    its report. No generation, no Langflow execution -- just re-scores the
    stored tool-call evidence with the current judge logic."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)
    settings = _settings(config=config, output_root=output_root)
    run_config = load_run_config(settings.config_path)
    from guardian.rejudge import rejudge_run
    run_dir = rejudge_run(settings, run_config, run_id=run)
    console.print(Panel.fit(f"Re-judge complete.\nRun: [bold]{run_dir}[/bold]"))


@app.command("remediate")
def remediate(
    run: str = typer.Option("latest", "--run", help="Run id to explain, or 'latest'."),
    config: Path | None = typer.Option(None, help="Path to guardian YAML config."),
    output_root: Path | None = typer.Option(None, help="Directory for run artifacts."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Ask the Guardian model to explain each CONFIRMED vulnerability (why it got
    through) and the specific fix. Writes remediation.md and updates the report."""
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO)
    settings = _settings(config=config, output_root=output_root)
    run_config = load_run_config(settings.config_path)
    from guardian.remediate import remediate_run
    run_dir = remediate_run(settings, run_config, run_id=run)
    console.print(Panel.fit(f"Explain-and-fix complete.\nRun: [bold]{run_dir}[/bold]"))


@app.command("show-report")
def show_report(report: Path) -> None:
    """Print the compact summary from a generated report.json file."""
    data = json.loads(report.read_text(encoding="utf-8"))
    summary = data.get("summary", {})
    console.print_json(data={"run_id": data.get("run_id"), "flow": data.get("flow"), "summary": summary})
