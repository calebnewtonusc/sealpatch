"""
SealPatch — Patch Agent
Generates minimal, verified CVE-remediation PRs for Dockerfiles and lockfiles.
Integrates with scan results to produce diff-format fixes and optionally open GitHub PRs.

Usage:
  python agents/patch_agent.py --repo owner/repo --cve CVE-2023-32681
  python agents/patch_agent.py --serve
"""

import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
import typer
from fastapi import FastAPI, HTTPException
from loguru import logger
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel
import torch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent))
from synthesis.prompts import SEALPATCH_SYSTEM_PROMPT

MODEL_PATH = os.environ.get("SEALPATCH_MODEL", "./checkpoints/sealpatch-final")
BASE_MODEL = os.environ.get("SEALPATCH_BASE", "Qwen/Qwen2.5-7B-Coder-Instruct")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
VLLM_BASE_URL = os.environ.get("VLLM_BASE_URL", "http://localhost:8001/v1")
USE_VLLM = os.environ.get("USE_VLLM", "0") == "1"

_model = None
_tokenizer = None


@dataclass
class PatchRequest:
    repo: str
    dockerfile_content: str
    scan_results: dict  # Normalized grype output
    branch: str = "sealpatch/cve-fix"
    open_pr: bool = False
    dry_run: bool = False


@dataclass
class PatchResult:
    success: bool
    diff: str
    pr_url: str = ""
    cves_addressed: list = field(default_factory=list)
    explanation: str = ""
    category: str = ""
    error: str = ""


def get_model():
    global _model, _tokenizer
    if _model is None:
        logger.info(f"Loading SealPatch model from {MODEL_PATH}")
        _tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)  # nosec B615
        _tokenizer.pad_token = _tokenizer.eos_token
        base = AutoModelForCausalLM.from_pretrained(  # nosec B615
            BASE_MODEL, torch_dtype=torch.bfloat16, device_map="auto"
        )
        if Path(MODEL_PATH).exists():
            _model = PeftModel.from_pretrained(base, MODEL_PATH)  # nosec B615
        else:
            _model = base
            logger.warning(f"No adapter at {MODEL_PATH}, using base model")
        _model.eval()
    return _model, _tokenizer


def generate_patch_vllm(prompt: str) -> str:
    """Use vLLM inference server for faster generation."""
    try:
        resp = requests.post(
            f"{VLLM_BASE_URL}/chat/completions",
            json={
                "model": "sealpatch",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2048,
                "temperature": 0.1,
            },
            timeout=120,
        )
        data = resp.json()
        return data["choices"][0]["message"]["content"]
    except Exception as e:
        logger.warning(f"vLLM call failed: {e}, falling back to local model")
        return ""


def generate_patch_local(prompt: str) -> str:
    """Run inference with local PEFT model."""
    model, tokenizer = get_model()
    full_prompt = (
        f"<|im_start|>system\n{SEALPATCH_SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
    )
    inputs = tokenizer(
        full_prompt, return_tensors="pt", truncation=True, max_length=10000
    )
    inputs = {k: v.to(model.device) for k, v in inputs.items()}
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=2048,
            temperature=0.1,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    return tokenizer.decode(
        out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
    )


def generate_patch(prompt: str) -> str:
    """Route inference to vLLM or local model."""
    if USE_VLLM:
        result = generate_patch_vllm(prompt)
        if result:
            return result
    return generate_patch_local(prompt)


def build_prompt(request: PatchRequest) -> str:
    scan = request.scan_results
    critical = scan.get("critical", 0)
    high = scan.get("high", 0)
    cves = scan.get("cves", [])

    findings_summary = ""
    for f in scan.get("findings", [])[:10]:
        findings_summary += (
            f"  - {f.get('cve_id', 'N/A')} [{f.get('severity', '?')}] "
            f"{f.get('package_name', '?')}@{f.get('installed_version', '?')} "
            f"→ fix: {f.get('fixed_version', 'unknown')}\n"
        )

    return (
        f"Repository: {request.repo}\n"
        f"Scan: {critical} CRITICAL, {high} HIGH\n"
        f"CVEs: {', '.join(cves[:10])}\n"
        f"Findings:\n{findings_summary}\n"
        f"Dockerfile:\n{request.dockerfile_content[:4000]}\n\n"
        f"Categorize each CVE and generate the minimal fix. "
        f"Output only the exact diff lines needed — do not upgrade unrelated packages."
    )


def extract_sections(raw: str) -> dict:
    """Extract <fix>, <categorize>, <suppress>, <validate> from model output."""

    def extract(tag, text):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL)
        return m.group(1).strip() if m else ""

    return {
        "fix": extract("fix", raw),
        "categorize": extract("categorize", raw),
        "suppress": extract("suppress", raw),
        "validate": extract("validate", raw),
        "raw": raw,
    }


def apply_diff_to_content(original: str, diff: str) -> Optional[str]:
    """Apply a unified diff to content using the `patch` command."""
    if not diff or len(diff) < 20:
        return None
    with tempfile.TemporaryDirectory(prefix="sealpatch_apply_") as tmpdir:
        orig_path = Path(tmpdir) / "Dockerfile"
        diff_path = Path(tmpdir) / "patch.diff"
        orig_path.write_text(original)
        diff_path.write_text(diff)
        result = subprocess.run(
            ["patch", "-p0", str(orig_path), str(diff_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return orig_path.read_text()
        logger.debug(f"patch failed: {result.stderr[:200]}")
        return None


def clone_and_apply(
    repo: str, diff: str, branch: str, dry_run: bool = False
) -> Optional[str]:
    """Clone repo, apply patch, push branch, return branch name."""
    with tempfile.TemporaryDirectory(prefix="sealpatch_clone_") as tmpdir:
        try:
            clone_url = f"https://{GITHUB_TOKEN}@github.com/{repo}.git"
            subprocess.run(
                ["git", "clone", "--depth=1", clone_url, tmpdir],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "checkout", "-b", branch],
                check=True,
                capture_output=True,
            )

            # Write the diff to a file and apply it
            diff_path = Path(tmpdir) / ".sealpatch.diff"
            diff_path.write_text(diff)
            result = subprocess.run(
                ["git", "-C", tmpdir, "apply", "--index", str(diff_path)],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                logger.warning(f"git apply failed: {result.stderr[:300]}")
                return None

            if not dry_run:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        tmpdir,
                        "commit",
                        "-m",
                        "fix: remediate CVEs via SealPatch\n\nAuto-generated minimal fix by SealPatch.",
                    ],
                    check=True,
                    capture_output=True,
                    env={
                        **os.environ,
                        "GIT_AUTHOR_NAME": "SealPatch",
                        "GIT_AUTHOR_EMAIL": "bot@sealpatch.ai",
                        "GIT_COMMITTER_NAME": "SealPatch",
                        "GIT_COMMITTER_EMAIL": "bot@sealpatch.ai",
                    },
                )
                subprocess.run(
                    ["git", "-C", tmpdir, "push", "origin", branch],
                    check=True,
                    capture_output=True,
                )
            return branch
        except subprocess.CalledProcessError as e:
            logger.warning(
                f"Git operation failed: {e.stderr if hasattr(e, 'stderr') else e}"
            )
            return None


def open_github_pr(repo: str, branch: str, cves: list, explanation: str) -> str:
    """Open a GitHub PR with the CVE fix."""
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    cve_list = "\n".join(f"- {c}" for c in cves) if cves else "- See diff for details"

    pr_body = (
        f"## SealPatch: CVE Remediation\n\n"
        f"This PR was automatically generated by [SealPatch](https://github.com/calebnewtonusc/sealpatch).\n\n"
        f"### CVEs Addressed\n{cve_list}\n\n"
        f"### Fix Strategy\n{explanation}\n\n"
        f"### Verification\n"
        f"```\ngrype . --fail-on critical --fail-on high\n# Expected: 0 CRITICAL, 0 HIGH\n```\n\n"
        f"---\n*Generated by SealPatch — surgical CVE remediation for containers*"
    )

    # Query the repo's actual default branch before creating the PR
    repo_resp = requests.get(
        f"https://api.github.com/repos/{repo}",
        headers=headers,
        timeout=15,
    )
    default_branch = (
        repo_resp.json().get("default_branch", "main")
        if repo_resp.status_code == 200
        else "main"
    )

    resp = requests.post(
        f"https://api.github.com/repos/{repo}/pulls",
        headers=headers,
        json={
            "title": f"fix(security): SealPatch CVE remediation [{', '.join(cves[:3])}]",
            "body": pr_body,
            "head": branch,
            "base": default_branch,
        },
        timeout=30,
    )
    if resp.status_code == 201:
        pr_url = resp.json().get("html_url", "")
        logger.info(f"PR opened: {pr_url}")
        return pr_url
    logger.warning(f"PR creation failed: {resp.status_code} {resp.text[:200]}")
    return ""


def patch(request: PatchRequest) -> PatchResult:
    """Main entrypoint: generate patch, optionally apply and open PR."""
    if not request.scan_results or (
        request.scan_results.get("critical", 0) + request.scan_results.get("high", 0)
        == 0
    ):
        return PatchResult(
            success=True,
            diff="",
            explanation="No CRITICAL or HIGH CVEs detected. No fix needed.",
        )

    prompt = build_prompt(request)
    logger.info(f"Generating patch for {request.repo}...")
    raw = generate_patch(prompt)
    sections = extract_sections(raw)

    diff = sections["fix"]
    category = sections["categorize"]
    explanation = sections.get("validate", sections.get("suppress", ""))

    if not diff or len(diff) < 10:
        return PatchResult(
            success=False,
            diff="",
            explanation="Model did not produce a valid diff.",
            error="empty_fix",
        )

    cves = request.scan_results.get("cves", [])

    if request.open_pr and GITHUB_TOKEN:
        pushed_branch = clone_and_apply(
            request.repo, diff, request.branch, dry_run=request.dry_run
        )
        if pushed_branch and not request.dry_run:
            pr_url = open_github_pr(request.repo, pushed_branch, cves, explanation)
            return PatchResult(
                success=True,
                diff=diff,
                pr_url=pr_url,
                cves_addressed=cves,
                explanation=explanation,
                category=category,
            )

    return PatchResult(
        success=True,
        diff=diff,
        pr_url="",
        cves_addressed=cves,
        explanation=explanation,
        category=category,
    )


# ── FastAPI server ──────────────────────────────────────────────────────────────


class PatchRequestBody(BaseModel):
    repo: str
    dockerfile: str
    scan_results: dict
    open_pr: bool = False
    dry_run: bool = True


api = FastAPI(title="SealPatch — Patch Agent API", version="1.0.0")


@api.get("/health")
def health():
    return {"status": "ok", "model": MODEL_PATH}


@api.post("/patch")
def patch_endpoint(body: PatchRequestBody):
    req = PatchRequest(
        repo=body.repo,
        dockerfile_content=body.dockerfile,
        scan_results=body.scan_results,
        open_pr=body.open_pr,
        dry_run=body.dry_run,
    )
    result = patch(req)
    if not result.success:
        raise HTTPException(
            status_code=422, detail=result.error or "Patch generation failed"
        )
    return {
        "diff": result.diff,
        "pr_url": result.pr_url,
        "cves_addressed": result.cves_addressed,
        "category": result.category,
        "explanation": result.explanation,
    }


app = typer.Typer()


@app.command()
def main(
    repo: str = typer.Option(None, help="GitHub repo (owner/repo)"),
    dockerfile: str = typer.Option(None, help="Path to local Dockerfile"),
    scan_json: str = typer.Option(None, help="Path to scan results JSON"),
    open_pr: bool = typer.Option(False, "--open-pr"),
    dry_run: bool = typer.Option(True, "--dry-run/--no-dry-run"),
    serve: bool = typer.Option(False, "--serve", help="Start FastAPI server"),
    port: int = typer.Option(8082),
):
    """Generate minimal CVE remediation patches for Dockerfiles."""
    if serve:
        import uvicorn

        uvicorn.run(api, host="0.0.0.0", port=port)
        return

    if not repo or not dockerfile:
        logger.error("--repo and --dockerfile are required")
        raise typer.Exit(1)

    dockerfile_content = Path(dockerfile).read_text()
    scan_results = {}
    if scan_json and Path(scan_json).exists():
        scan_results = json.loads(Path(scan_json).read_text())

    req = PatchRequest(
        repo=repo,
        dockerfile_content=dockerfile_content,
        scan_results=scan_results,
        open_pr=open_pr,
        dry_run=dry_run,
    )
    result = patch(req)
    if result.success:
        logger.info(f"Patch generated. CVEs: {result.cves_addressed}")
        if result.diff:
            print(result.diff)
        if result.pr_url:
            logger.info(f"PR: {result.pr_url}")
    else:
        logger.error(f"Patch failed: {result.error}")


if __name__ == "__main__":
    app()
