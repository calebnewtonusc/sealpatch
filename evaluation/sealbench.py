"""
SealBench — SealPatch Evaluation Suite
500 CVE remediation scenarios across all 5 CVE categories and 5 ecosystems.

Usage:
  python evaluation/sealbench.py --model checkpoints/sealpatch-final
  python evaluation/sealbench.py --model checkpoints/sealpatch-final --category APP_DEP_CVE
"""

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import torch
import typer
from loguru import logger
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.cve_taxonomy import CVECategory
from synthesis.prompts import SEALPATCH_SYSTEM_PROMPT


@dataclass
class SealBenchCase:
    id: str
    ecosystem: str
    cve_category: CVECategory
    dockerfile: str
    cve_ids: list[str]
    critical_before: int
    high_before: int
    correct_fix_diff: str
    is_dev_only: bool = False
    notes: str = ""


@dataclass
class SealBenchResult:
    case_id: str
    cve_category: CVECategory
    cves_categorized_correctly: bool
    fix_generated: bool
    fix_applies: bool
    cve_eliminated: bool  # Via Grype rescan or heuristic
    behavior_preserved: bool  # CI green heuristic
    is_minimal: bool
    latency: float


# ── Embedded cases ─────────────────────────────────────────────────────────────

SEALBENCH_CASES: list[SealBenchCase] = [
    SealBenchCase(
        id="base_image_001_ubuntu_openssl",
        ecosystem="python",
        cve_category=CVECategory.BASE_IMAGE,
        dockerfile="FROM ubuntu:20.04\nRUN apt-get update && apt-get install -y libssl1.1\nCOPY . .\nCMD python app.py",
        cve_ids=["CVE-2022-0778"],
        critical_before=1, high_before=0,
        correct_fix_diff="--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1 +1 @@\n-FROM ubuntu:20.04\n+FROM ubuntu:22.04",
        notes="OpenSSL CVE fixed in Ubuntu 22.04+",
    ),
    SealBenchCase(
        id="app_dep_001_requests_ssrf",
        ecosystem="python",
        cve_category=CVECategory.APP_DEP,
        dockerfile="FROM python:3.11-slim\nCOPY requirements.txt .\nRUN pip install -r requirements.txt\nCOPY . .\nCMD python app.py",
        cve_ids=["CVE-2023-32681"],
        critical_before=0, high_before=1,
        correct_fix_diff="--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-requests==2.28.0\n+requests==2.31.0",
        notes="requests SSRF CVE patched in 2.31.0",
    ),
    SealBenchCase(
        id="dev_only_001_pytest",
        ecosystem="python",
        cve_category=CVECategory.APP_DEP,
        dockerfile="FROM python:3.11-slim\nCOPY requirements.txt dev-requirements.txt ./\nRUN pip install -r requirements.txt -r dev-requirements.txt",
        cve_ids=["CVE-2024-FAKE-PYTEST"],
        critical_before=0, high_before=1,
        correct_fix_diff="",  # No fix — dev-only
        is_dev_only=True,
        notes="pytest CVE in dev-requirements.txt — should be suppressed",
    ),
    SealBenchCase(
        id="runtime_001_node",
        ecosystem="javascript",
        cve_category=CVECategory.RUNTIME,
        dockerfile="FROM node:18.12-alpine\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD node server.js",
        cve_ids=["CVE-2023-30581"],
        critical_before=1, high_before=0,
        correct_fix_diff="--- a/Dockerfile\n+++ b/Dockerfile\n@@ -1 +1 @@\n-FROM node:18.12-alpine\n+FROM node:18.20-alpine",
        notes="Node.js 18.12 had permission model bypass CVE; 18.20 fixes it",
    ),
]


def load_cases_from_dir(cases_dir: Path) -> list[SealBenchCase]:
    cases = list(SEALBENCH_CASES)
    if cases_dir.exists():
        for f in cases_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                # Convert cve_category string to CVECategory enum if needed.
                if "cve_category" in data and isinstance(data["cve_category"], str):
                    data["cve_category"] = CVECategory(data["cve_category"])
                cases.append(SealBenchCase(**data))
            except Exception:
                pass
    return cases


def load_model(model_path: str):
    base_name = "Qwen/Qwen2.5-7B-Coder-Instruct"
    tokenizer = AutoTokenizer.from_pretrained(base_name)
    tokenizer.pad_token = tokenizer.eos_token
    base = AutoModelForCausalLM.from_pretrained(base_name, torch_dtype=torch.bfloat16, device_map="auto")
    if Path(model_path).exists():
        model = PeftModel.from_pretrained(base, model_path)
    else:
        model = base
        logger.warning(f"No adapter at {model_path}, using base model")
    model.eval()
    return model, tokenizer


def run_inference(model, tokenizer, case: SealBenchCase) -> str:
    scan_info = f"{case.critical_before} CRITICAL, {case.high_before} HIGH\nCVEs: {', '.join(case.cve_ids)}"
    prompt = (
        f"<|im_start|>system\n{SEALPATCH_SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n"
        f"Ecosystem: {case.ecosystem}\n"
        f"Scan: {scan_info}\n"
        f"Artifact:\n{case.dockerfile}\n\n"
        f"Remediate all CVEs.\n"
        f"<|im_end|>\n<|im_start|>assistant\n"
    )
    inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=10000)
    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=1024, temperature=0.1, do_sample=False,
                             pad_token_id=tokenizer.eos_token_id)
    return tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True)


def evaluate_result(case: SealBenchCase, generated: str, latency: float) -> SealBenchResult:
    fix_match = re.search(r"<fix>(.*?)</fix>", generated, re.DOTALL)
    fix_text = fix_match.group(1).strip() if fix_match else ""

    cat_match = re.search(r"<categorize>(.*?)</categorize>", generated, re.DOTALL)
    cat_text = cat_match.group(1).strip() if cat_match else ""
    correct_cat = case.cve_category.value in cat_text

    if case.is_dev_only:
        suppress_match = re.search(r"<suppress>(.*?)</suppress>", generated, re.DOTALL)
        suppressed = suppress_match and len(suppress_match.group(1).strip()) > 10
        return SealBenchResult(
            case_id=case.id, cve_category=case.cve_category,
            cves_categorized_correctly=correct_cat,
            fix_generated=False, fix_applies=True,
            cve_eliminated=suppressed, behavior_preserved=True, is_minimal=True,
            latency=latency,
        )

    fix_applies = "---" in fix_text and "+++" in fix_text and len(fix_text) > 20

    # Token-similarity check: does the generated fix share key tokens with the ground-truth diff?
    cve_eliminated = False
    if fix_text and case.correct_fix_diff:
        gt_tokens = set(case.correct_fix_diff.lower().split())
        gen_tokens = set(fix_text.lower().split())
        if gt_tokens:
            overlap = len(gt_tokens & gen_tokens) / len(gt_tokens)
            cve_eliminated = overlap >= 0.4  # 40% token overlap with ground-truth fix

    gt_lines = len([l for l in case.correct_fix_diff.split("\n")
                    if l.startswith(("+", "-")) and not l.startswith(("---", "+++"))])
    gen_lines = len([l for l in fix_text.split("\n")
                     if l.startswith(("+", "-")) and not l.startswith(("---", "+++"))])
    is_minimal = gen_lines <= max(gt_lines * 2, 5) if gt_lines > 0 else gen_lines <= 10

    # behavior_preserved: True only if the fix doesn't remove FROM/CMD/ENTRYPOINT entirely
    behavior_preserved = False
    if fix_applies:
        removed_lines = [l[1:].strip() for l in fix_text.split("\n") if l.startswith("-") and not l.startswith("---")]
        critical_removed = any(
            any(instr in l.upper() for instr in ("FROM ", "CMD ", "ENTRYPOINT "))
            for l in removed_lines
        )
        behavior_preserved = not critical_removed

    return SealBenchResult(
        case_id=case.id, cve_category=case.cve_category,
        cves_categorized_correctly=correct_cat,
        fix_generated=bool(fix_text), fix_applies=fix_applies,
        cve_eliminated=cve_eliminated, behavior_preserved=behavior_preserved,
        is_minimal=is_minimal, latency=latency,
    )


app = typer.Typer()


@app.command()
def main(
    model_path: str = typer.Option("./checkpoints/sealpatch-final"),
    cases_dir: Path = typer.Option(Path("data/seal_bench")),
    category: str = typer.Option(None),
    output_json: Path = typer.Option(Path("results/sealbench_results.json")),
    max_cases: int = typer.Option(500),
):
    """Run SealBench evaluation on SealPatch model."""
    cases = load_cases_from_dir(cases_dir)
    if category:
        cases = [c for c in cases if c.cve_category.value == category]
    cases = cases[:max_cases]
    logger.info(f"Evaluating {len(cases)} cases")

    model, tokenizer = load_model(model_path)
    results = []
    for i, case in enumerate(cases):
        t0 = time.time()
        generated = run_inference(model, tokenizer, case)
        result = evaluate_result(case, generated, time.time() - t0)
        results.append(result)
        logger.info(f"[{i+1}/{len(cases)}] {case.id}: cat={result.cves_categorized_correctly} elim={result.cve_eliminated}")

    n = len(results)
    if not n:
        logger.warning("No results to summarize")
        summary = {"total": 0}
    else:
        summary = {
            "total": n,
            "categorization_accuracy": sum(1 for r in results if r.cves_categorized_correctly) / n,
            "cve_elimination_rate": sum(1 for r in results if r.cve_eliminated) / n,
            "fix_application_rate": sum(1 for r in results if r.fix_applies) / n,
            "minimality_rate": sum(1 for r in results if r.is_minimal) / n,
            "avg_latency": sum(r.latency for r in results) / n,
        }
    logger.info(f"\nSealBench Summary: {summary}")

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps({"summary": summary}, indent=2))
    logger.info(f"Results saved to {output_json}")


if __name__ == "__main__":
    app()
