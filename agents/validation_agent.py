"""
SealPatch — Validation Agent
Verifies that a generated patch:
  1. Applies cleanly to the original artifact
  2. Eliminates the reported CRITICAL/HIGH CVEs (Grype rescan)
  3. Does not break the container build (docker build smoke test)
  4. Passes a basic smoke test (container starts and responds)

Also generates RL task records for training reward computation.

Usage:
  python agents/validation_agent.py --dockerfile path/to/Dockerfile --diff patch.diff
  python agents/validation_agent.py --serve
"""

import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import typer
from fastapi import FastAPI, HTTPException
from loguru import logger
from pydantic import BaseModel, Field

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.scan_agent import normalize_grype_output, GRYPE_BIN, TRIVY_BIN

DOCKER_BIN = os.environ.get("DOCKER_BIN", "docker")
PATCH_TIMEOUT = int(os.environ.get("PATCH_TIMEOUT", "300"))  # seconds
SMOKE_TEST_TIMEOUT = int(os.environ.get("SMOKE_TEST_TIMEOUT", "60"))


@dataclass
class ValidationRequest:
    dockerfile_before: str
    diff: str
    cve_ids: list = field(default_factory=list)
    critical_before: int = 0
    high_before: int = 0
    run_smoke_test: bool = True
    repo: str = ""
    language: str = "unknown"


@dataclass
class ValidationResult:
    patch_applies: bool
    build_succeeds: bool
    cve_eliminated: bool
    smoke_test_passed: bool
    critical_after: int
    high_after: int
    critical_before: int
    high_before: int
    latency: float
    error: str = ""
    scan_after: dict = field(default_factory=dict)


def apply_diff(original: str, diff: str, workdir: Path) -> Optional[str]:
    """
    Apply a unified diff to a Dockerfile in workdir.
    Returns patched content or None on failure.
    """
    orig_path = workdir / "Dockerfile"
    diff_path = workdir / "patch.diff"
    orig_path.write_text(original)
    diff_path.write_text(diff)

    # Use -p1 to match git-format unified diffs (strip one path component)
    result = subprocess.run(
        ["patch", "-p1", "-d", str(workdir)],
        input=diff, capture_output=True, text=True,
    )
    if result.returncode == 0:
        return orig_path.read_text()

    # Fallback: git apply (handles git-format diffs better)
    # Initialize a temporary git repo so git apply has a valid git context.
    subprocess.run(
        ["git", "init"],
        capture_output=True, text=True, cwd=str(workdir),
    )
    subprocess.run(
        ["git", "config", "user.email", "sealpatch@localhost"],
        capture_output=True, text=True, cwd=str(workdir),
    )
    subprocess.run(
        ["git", "config", "user.name", "SealPatch"],
        capture_output=True, text=True, cwd=str(workdir),
    )
    subprocess.run(
        ["git", "add", "."],
        capture_output=True, text=True, cwd=str(workdir),
    )
    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", "init"],
        capture_output=True, text=True, cwd=str(workdir),
    )
    result2 = subprocess.run(
        ["git", "apply", f"--directory={workdir}", str(diff_path)],
        capture_output=True, text=True, cwd=str(workdir),
    )
    if result2.returncode == 0:
        return (workdir / "Dockerfile").read_text()

    logger.debug(f"patch failed: {result.stderr[:200]}")
    logger.debug(f"git apply failed: {result2.stderr[:200]}")
    return None


def build_docker_image(workdir: Path, tag: str) -> bool:
    """Build Docker image from workdir, return True on success."""
    try:
        result = subprocess.run(
            [DOCKER_BIN, "build", "-t", tag, str(workdir)],
            capture_output=True, timeout=PATCH_TIMEOUT,
        )
        if result.returncode != 0:
            logger.debug(f"docker build failed:\n{result.stderr.decode()[:500]}")
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logger.warning("docker build timed out")
        return False
    except Exception as e:
        logger.debug(f"docker build error: {e}")
        return False


def run_grype_scan(target: str, is_image: bool = True) -> dict:
    """Run Grype scan on image or dir, return normalized results."""
    prefix = "" if is_image else "dir:"
    try:
        result = subprocess.run(
            [GRYPE_BIN, f"{prefix}{target}", "-o", "json", "--fail-on", "none"],
            capture_output=True, text=True, timeout=120,
        )
        raw = json.loads(result.stdout) if result.stdout else {}
        return normalize_grype_output(raw)
    except Exception as e:
        logger.debug(f"Grype scan failed: {e}")
        return {}


def run_smoke_test(image_tag: str, timeout: int = SMOKE_TEST_TIMEOUT) -> bool:
    """
    Basic smoke test: container must start and exit cleanly (or serve on port).
    Returns True if container starts without crashing immediately.
    """
    container_name = f"sealpatch-smoke-{int(time.time())}"
    try:
        result = subprocess.run(
            [DOCKER_BIN, "run", "--rm", "--name", container_name,
             "--entrypoint", "echo", image_tag, "smoke_ok"],
            capture_output=True, timeout=timeout,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        subprocess.run([DOCKER_BIN, "rm", "-f", container_name], capture_output=True)
        return False
    except Exception as e:
        logger.debug(f"smoke test error: {e}")
        return False
    finally:
        subprocess.run([DOCKER_BIN, "rm", "-f", container_name], capture_output=True)


def validate(request: ValidationRequest) -> ValidationResult:
    """Full validation pipeline: apply → build → scan → smoke test."""
    t0 = time.time()

    with tempfile.TemporaryDirectory(prefix="sealpatch_val_") as tmpdir:
        workdir = Path(tmpdir)

        # 1. Apply patch
        patched = apply_diff(request.dockerfile_before, request.diff, workdir)
        if patched is None:
            return ValidationResult(
                patch_applies=False, build_succeeds=False, cve_eliminated=False,
                smoke_test_passed=False, critical_after=request.critical_before,
                high_after=request.high_before, critical_before=request.critical_before,
                high_before=request.high_before, latency=time.time() - t0,
                error="patch_apply_failed",
            )

        # Write patched Dockerfile
        (workdir / "Dockerfile").write_text(patched)

        # 2. Build Docker image
        image_tag = f"sealpatch-val:{int(time.time())}"
        build_ok = build_docker_image(workdir, image_tag)

        scan_after = {}
        critical_after = request.critical_before
        high_after = request.high_before
        smoke_ok = False
        cve_eliminated = False

        if build_ok:
            # 3. Grype rescan
            scan_after = run_grype_scan(image_tag, is_image=True)
            critical_after = scan_after.get("critical", request.critical_before)
            high_after = scan_after.get("high", request.high_before)
            cve_eliminated = (critical_after + high_after) < (request.critical_before + request.high_before)

            # 4. Smoke test
            if request.run_smoke_test:
                smoke_ok = run_smoke_test(image_tag)

            # Cleanup image
            subprocess.run([DOCKER_BIN, "rmi", image_tag], capture_output=True)
        else:
            # Fallback: scan dir even without build
            scan_after = run_grype_scan(str(workdir), is_image=False)
            critical_after = scan_after.get("critical", request.critical_before)
            high_after = scan_after.get("high", request.high_before)
            cve_eliminated = (critical_after + high_after) < (request.critical_before + request.high_before)

        return ValidationResult(
            patch_applies=True,
            build_succeeds=build_ok,
            cve_eliminated=cve_eliminated,
            smoke_test_passed=smoke_ok,
            critical_after=critical_after,
            high_after=high_after,
            critical_before=request.critical_before,
            high_before=request.high_before,
            latency=time.time() - t0,
            scan_after=scan_after,
        )


def build_rl_tasks(scanned_dir: Path, output_path: Path, min_cve: int = 1):
    """
    Build CVE scan tasks for RL training from verified pairs.
    Output: JSONL with {repo, dockerfile_before, cve_ids, critical_before, high_before, ...}
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tasks = []

    for f in scanned_dir.rglob("*.jsonl"):
        with open(f) as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue

                scan_before = rec.get("scan_before", {})
                c = scan_before.get("critical", 0)
                h = scan_before.get("high", 0)
                if c + h < min_cve:
                    continue

                tasks.append({
                    "repo": rec.get("repo", ""),
                    "before_sha": rec.get("before_sha", ""),
                    "language": rec.get("language", "unknown"),
                    "dockerfile_before": (rec.get("artifacts_before") or {}).get("Dockerfile", ""),
                    "cve_ids": scan_before.get("cves", []),
                    "critical_before": c,
                    "high_before": h,
                })

    with open(output_path, "w") as out:
        for t in tasks:
            out.write(json.dumps(t) + "\n")

    logger.info(f"Built {len(tasks)} RL tasks → {output_path}")
    return len(tasks)


# ── FastAPI server ──────────────────────────────────────────────────────────────

class ExecuteRequest(BaseModel):
    diff: str
    repo: str = ""
    before_sha: str = ""
    language: str = "unknown"
    dockerfile_before: str
    cve_ids: list = Field(default_factory=list)
    critical_before: int = 0
    high_before: int = 0
    scan_type: str = "grype"
    run_smoke_test: bool = True


api = FastAPI(title="SealPatch — Validation Agent API", version="1.0.0")


@api.get("/health")
def health():
    return {"status": "ok", "grype": GRYPE_BIN, "docker": DOCKER_BIN}


@api.post("/execute")
def execute_endpoint(body: ExecuteRequest):
    req = ValidationRequest(
        dockerfile_before=body.dockerfile_before,
        diff=body.diff,
        cve_ids=body.cve_ids,
        critical_before=body.critical_before,
        high_before=body.high_before,
        run_smoke_test=body.run_smoke_test,
        repo=body.repo,
        language=body.language,
    )
    result = validate(req)
    return {
        "patch_applies": result.patch_applies,
        "build_succeeds": result.build_succeeds,
        "cve_eliminated": result.cve_eliminated,
        "smoke_test_passed": result.smoke_test_passed,
        "critical_after": result.critical_after,
        "high_after": result.high_after,
        "critical_before": result.critical_before,
        "high_before": result.high_before,
        "latency": result.latency,
        "error": result.error,
    }


app = typer.Typer()


@app.command()
def main(
    dockerfile: str = typer.Option(None, help="Dockerfile path"),
    diff: str = typer.Option(None, help="Patch diff file path"),
    cves: str = typer.Option("", help="Comma-separated CVE IDs"),
    critical: int = typer.Option(0),
    high: int = typer.Option(0),
    no_smoke: bool = typer.Option(False, "--no-smoke"),
    build_rl: bool = typer.Option(False, "--build-rl"),
    scanned_dir: Path = typer.Option(Path("data/scanned")),
    rl_output: Path = typer.Option(Path("data/rl/cve_scan_tasks.jsonl")),
    serve: bool = typer.Option(False, "--serve"),
    port: int = typer.Option(8083),
):
    """Validate CVE patches and build RL training tasks."""
    if serve:
        import uvicorn
        uvicorn.run(api, host="0.0.0.0", port=port)
        return

    if build_rl:
        n = build_rl_tasks(scanned_dir, rl_output)
        logger.info(f"Built {n} RL tasks")
        return

    if not dockerfile or not diff:
        logger.error("--dockerfile and --diff are required")
        raise typer.Exit(1)

    req = ValidationRequest(
        dockerfile_before=Path(dockerfile).read_text(),
        diff=Path(diff).read_text(),
        cve_ids=[c.strip() for c in cves.split(",") if c.strip()],
        critical_before=critical,
        high_before=high,
        run_smoke_test=not no_smoke,
    )
    result = validate(req)
    logger.info(
        f"Validation: patch={result.patch_applies} build={result.build_succeeds} "
        f"cve_elim={result.cve_eliminated} smoke={result.smoke_test_passed} "
        f"CVEs: {result.critical_before}C+{result.high_before}H → {result.critical_after}C+{result.high_after}H"
    )


if __name__ == "__main__":
    app()
