"""
SealPatch Master Pipeline
Orchestrates data → training → evaluation for the CVE remediation specialist.

Usage:
  python pipeline.py                    # Full pipeline
  python pipeline.py --stage discovery  # CVE DB sync + repo collection
  python pipeline.py --stage synthesis  # Generate training pairs
  python pipeline.py --stage train      # 3-stage training
  python pipeline.py --stage eval       # SealBench evaluation
"""

import os
import subprocess
from pathlib import Path

import typer
from loguru import logger
from rich.console import Console
from rich.table import Table

console = Console()
app = typer.Typer()

STAGES = [
    {
        "name": "check_env",
        "description": "Verify environment, scanners (Grype/Trivy), and API keys",
        "cmd": "bash scripts/check_env.sh",
        "phase": "discovery",
        "estimated_hours": 0.1,
    },
    {
        "name": "sync_cve_db",
        "description": "Sync OSV, NVD, and GitHub Advisory databases",
        "cmd": "python discovery/cve_database.py --sync-all",
        "phase": "discovery",
        "estimated_hours": 2.0,
    },
    {
        "name": "crawl_dockerfiles",
        "description": "Collect Dockerfiles + lockfiles from top 20k GitHub repos",
        "cmd": "python discovery/dockerfile_crawler.py --repos 20000 --workers 30",
        "phase": "discovery",
        "estimated_hours": 4.0,
    },
    {
        "name": "scan_artifacts",
        "description": "Run Grype/Trivy on collected artifacts (parallel scan)",
        "cmd": "python agents/scan_agent.py --batch-mode --workers 20",
        "phase": "discovery",
        "estimated_hours": 6.0,
    },
    {
        "name": "start_vllm",
        "description": "Launch Qwen2.5-72B synthesis servers",
        "cmd": "bash scripts/start_vllm.sh",
        "phase": "synthesis",
        "estimated_hours": 0.5,
    },
    {
        "name": "synthesize_remediation_pairs",
        "description": "Synthesize CVE-fix pairs from OSV/NVD advisories (Stream 2)",
        "cmd": "python synthesis/remediation_synthesizer.py --concurrency 32",
        "phase": "synthesis",
        "estimated_hours": 10.0,
    },
    {
        "name": "validate_pairs",
        "description": "Sandbox-validate synthesized pairs (Grype before/after)",
        "cmd": "python agents/validation_agent.py --validate-synthesized",
        "phase": "validation",
        "estimated_hours": 3.0,
    },
    {
        "name": "build_dpo_pairs",
        "description": "Build preference pairs (surgical fix vs. blanket upgrade)",
        "cmd": "python synthesis/remediation_synthesizer.py --dpo-mode",
        "phase": "validation",
        "estimated_hours": 2.0,
    },
    {
        "name": "train_sft",
        "description": "Stage 1: SFT on CVE remediation pairs (7h on 18× A6000)",
        "cmd": "deepspeed --num_gpus=18 training/train.py --deepspeed training/configs/deepspeed_zero3.json",
        "phase": "train",
        "estimated_hours": 7.0,
    },
    {
        "name": "train_rl",
        "description": "Stage 2: CVE-RL GRPO (4h on 18× A6000)",
        "cmd": "deepspeed --num_gpus=18 training/train_rl.py --deepspeed training/configs/deepspeed_zero3.json",
        "phase": "train",
        "estimated_hours": 4.0,
    },
    {
        "name": "train_dpo",
        "description": "Stage 3: DPO on fix minimality preferences (2h)",
        "cmd": "deepspeed --num_gpus=18 training/train_dpo.py --deepspeed training/configs/deepspeed_zero3.json",
        "phase": "train",
        "estimated_hours": 2.0,
    },
    {
        "name": "seal_bench",
        "description": "SealBench evaluation on 500 CVE scenarios",
        "cmd": "python evaluation/sealbench.py --model checkpoints/sealpatch-final",
        "phase": "eval",
        "estimated_hours": 5.0,
    },
    {
        "name": "deploy",
        "description": "Launch SealPatch API (Docker Compose)",
        "cmd": "docker compose -f deploy/docker-compose.yml up -d",
        "phase": "deploy",
        "estimated_hours": 0.2,
    },
]


def run_stage(stage: dict, dry_run: bool = False) -> bool:
    console.print(f"\n[bold cyan]▶ {stage['name']}[/bold cyan]: {stage['description']}")
    console.print(f"  [dim]{stage['cmd']}[/dim]")
    if dry_run:
        console.print("  [yellow](dry run)[/yellow]")
        return True
    result = subprocess.run(stage["cmd"], shell=True)
    if result.returncode != 0:
        console.print(f"  [red]✗ Failed (exit {result.returncode})[/red]")
        return False
    console.print("  [green]✓ Complete[/green]")
    return True


@app.command()
def main(
    stage: str = typer.Option(None, help="Phase: discovery|synthesis|validation|train|eval|deploy"),
    from_stage: str = typer.Option(None, help="Resume from this stage name"),
    dry_run: bool = typer.Option(False, help="Print commands without executing"),
    list_stages: bool = typer.Option(False, "--list", help="List all stages"),
):
    """SealPatch: full training pipeline from CVE data to deployed remediation agent."""
    if list_stages:
        table = Table(title="SealPatch Pipeline Stages")
        table.add_column("Stage", style="cyan")
        table.add_column("Phase")
        table.add_column("Description")
        table.add_column("Est. Hours", justify="right")
        for s in STAGES:
            table.add_row(s["name"], s["phase"], s["description"], str(s["estimated_hours"]))
        console.print(table)
        total = sum(s["estimated_hours"] for s in STAGES)
        console.print(f"\nTotal: {total:.1f} hours")
        return

    stages_to_run = STAGES
    if stage:
        stages_to_run = [s for s in STAGES if s["phase"] == stage]
    elif from_stage:
        names = [s["name"] for s in STAGES]
        if from_stage in names:
            stages_to_run = STAGES[names.index(from_stage):]
        else:
            valid = ", ".join(names)
            console.print(f"[red]Unknown stage: '{from_stage}'. Valid stages: {valid}[/red]")
            raise typer.Exit(1)

    total_hours = sum(s["estimated_hours"] for s in stages_to_run)
    console.print(f"\n[bold]SealPatch Pipeline[/bold] — {len(stages_to_run)} stages, ~{total_hours:.0f}h")

    for s in stages_to_run:
        if not run_stage(s, dry_run):
            console.print(f"\n[red bold]Pipeline failed at: {s['name']}[/red bold]")
            console.print(f"Resume: python pipeline.py --from-stage {s['name']}")
            raise typer.Exit(1)

    console.print("\n[green bold]Pipeline complete.[/green bold]")


if __name__ == "__main__":
    app()
