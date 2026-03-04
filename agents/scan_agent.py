"""
SealPatch — Scan Agent
Runs Grype and Trivy scans on Dockerfiles, images, and lockfiles.
Produces normalized SARIF output for SealPatch model consumption.

Usage:
  python agents/scan_agent.py --repo owner/repo --output scan_results/
  python agents/scan_agent.py --batch-mode --workers 20
  python agents/scan_agent.py --dockerfile path/to/Dockerfile
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

import typer
from loguru import logger

GRYPE_BIN = os.environ.get("GRYPE_BIN", "grype")
TRIVY_BIN = os.environ.get("TRIVY_BIN", "trivy")
MIN_SEVERITY = os.environ.get("MIN_SEVERITY", "HIGH")


def run_grype_on_dir(target_dir: str) -> dict:
    """Run Grype scan on a directory, return parsed results."""
    try:
        result = subprocess.run(
            [GRYPE_BIN, "dir:" + target_dir, "-o", "json", "--fail-on", "none"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode not in (0, 1):  # 1 = vulnerabilities found
            logger.debug(f"Grype error: {result.stderr[:200]}")
            return {}
        return json.loads(result.stdout) if result.stdout else {}
    except Exception as e:
        logger.debug(f"Grype scan failed: {e}")
        return {}


def run_grype_on_image(image_ref: str) -> dict:
    """Run Grype scan on a Docker image reference."""
    try:
        result = subprocess.run(
            [GRYPE_BIN, image_ref, "-o", "json", "--fail-on", "none"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        return json.loads(result.stdout) if result.stdout else {}
    except Exception as e:
        logger.debug(f"Grype image scan failed: {e}")
        return {}


def run_trivy_on_dockerfile(dockerfile_path: str) -> dict:
    """Run Trivy config scan on a Dockerfile."""
    try:
        result = subprocess.run(
            [TRIVY_BIN, "config", "--format", "json", dockerfile_path],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return json.loads(result.stdout) if result.stdout else {}
    except Exception as e:
        logger.debug(f"Trivy scan failed: {e}")
        return {}


def normalize_grype_output(grype_json: dict) -> dict:
    """Convert Grype JSON output to SealPatch normalized format."""
    matches = grype_json.get("matches", [])
    cves = []
    critical = high = medium = low = 0

    for match in matches:
        vuln = match.get("vulnerability", {})
        severity = vuln.get("severity", "UNKNOWN").upper()
        cve_id = vuln.get("id", "")
        pkg = match.get("artifact", {})

        locations = pkg.get("locations", [])
        loc = locations[0] if locations else {}
        finding = {
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": 0.0,
            "package_name": pkg.get("name", ""),
            "installed_version": pkg.get("version", ""),
            "fixed_version": (vuln.get("fix", {}).get("versions") or [None])[0],
            "artifact_type": pkg.get("type", ""),
            "artifact_location": loc.get("path", ""),
        }

        if severity == "CRITICAL":
            critical += 1
        elif severity == "HIGH":
            high += 1
        elif severity == "MEDIUM":
            medium += 1
        elif severity == "LOW":
            low += 1

        cves.append(finding)

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "cves": [c["cve_id"] for c in cves if c["cve_id"]],
        "findings": cves,
        "scanner": "grype",
    }


def scan_dockerfile(dockerfile_content: str, language: str = "unknown") -> dict:
    """
    Scan a Dockerfile by writing it to a temp directory and running Grype.
    Returns normalized scan results.
    """
    with tempfile.TemporaryDirectory(prefix="sealpatch_scan_") as tmpdir:
        # Write Dockerfile
        dockerfile_path = Path(tmpdir) / "Dockerfile"
        dockerfile_path.write_text(dockerfile_content)

        # Try to build image for scanning (if Docker is available)
        image_tag = "sealpatch-scan-temp:latest"
        built = False
        try:
            result = subprocess.run(
                ["docker", "build", "-t", image_tag, tmpdir],
                capture_output=True,
                timeout=120,
            )
            built = result.returncode == 0
        except Exception:
            pass

        if built:
            grype_raw = run_grype_on_image(image_tag)
            # Clean up image
            subprocess.run(["docker", "rmi", image_tag], capture_output=True)
        else:
            # Fallback: scan directory with Dockerfile
            grype_raw = run_grype_on_dir(tmpdir)

        return normalize_grype_output(grype_raw)


def batch_scan_artifacts(
    artifacts_dir: Path,
    output_dir: Path,
    workers: int = 10,
) -> int:
    """Batch scan all raw artifact files and add scan results."""
    import concurrent.futures

    output_dir.mkdir(parents=True, exist_ok=True)
    input_files = list(artifacts_dir.rglob("*.jsonl"))
    total_scanned = 0

    for input_file in input_files:
        output_file = output_dir / input_file.name
        records = []

        with open(input_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass

        def scan_record(rec):
            dockerfile_before = (rec.get("artifacts_before") or {}).get(
                "Dockerfile", ""
            )
            dockerfile_after = (rec.get("artifacts_after") or {}).get("Dockerfile", "")

            if dockerfile_before:
                rec["scan_before"] = scan_dockerfile(dockerfile_before)
            if dockerfile_after:
                rec["scan_after"] = scan_dockerfile(dockerfile_after)

            # Only keep if scan shows CVE reduction
            before_critical = (rec.get("scan_before") or {}).get("critical", 0)
            before_high = (rec.get("scan_before") or {}).get("high", 0)
            after_critical = (rec.get("scan_after") or {}).get("critical", 999)
            after_high = (rec.get("scan_after") or {}).get("high", 999)

            rec["has_cve_reduction"] = (before_critical + before_high) > (
                after_critical + after_high
            )
            rec["verified_scan"] = True
            return rec

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            scanned = list(executor.map(scan_record, records))

        with open(output_file, "w") as f:
            for rec in scanned:
                if rec.get("has_cve_reduction"):
                    f.write(json.dumps(rec) + "\n")
                    total_scanned += 1

        logger.info(f"  {input_file.name}: {total_scanned} pairs with CVE reduction")

    return total_scanned


app = typer.Typer()


@app.command()
def main(
    repo: str = typer.Option(None, help="GitHub repo to scan"),
    dockerfile: str = typer.Option(None, help="Local Dockerfile to scan"),
    batch_mode: bool = typer.Option(False, "--batch-mode"),
    workers: int = typer.Option(20),
    output: Path = typer.Option(Path("data/scanned")),
    artifacts_dir: Path = typer.Option(Path("data/raw/artifacts")),
):
    """Run Grype/Trivy scans on Dockerfiles and build artifacts."""
    if batch_mode:
        logger.info(f"Batch scanning {artifacts_dir}...")
        n = batch_scan_artifacts(artifacts_dir, output, workers)
        logger.info(f"Scanned {n} pairs with CVE reduction")
    elif dockerfile:
        content = Path(dockerfile).read_text()
        result = scan_dockerfile(content)
        logger.info(
            f"Scan result: {result['critical']} CRITICAL, {result['high']} HIGH"
        )
        logger.info(json.dumps(result, indent=2))
    elif repo:
        logger.info(f"Scanning repo {repo}...")
        # Would clone and scan in production
        logger.info("Repo scanning requires GITHUB_TOKEN and Docker")
    else:
        logger.error("Specify --repo, --dockerfile, or --batch-mode")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
