"""
docker_hub_scanner.py - Docker Hub official image Dockerfile collection and analysis.

Pulls top 1000 Docker Hub official/verified images.
For each image, fetches the Dockerfile from the GitHub source repo.
Analyzes packages for pinned vs unpinned versions.

Creates (dockerfile_with_issues, issues_found) pairs for training.

Docker Hub API: https://hub.docker.com/v2/
GitHub: https://github.com/docker-library/  (official images)

Usage:
    export GITHUB_TOKEN=your_token
    python discovery/docker_hub_scanner.py
    python discovery/docker_hub_scanner.py --official-only
    python discovery/docker_hub_scanner.py --max-images 500
"""

import argparse
import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

DATA_DIR = Path(__file__).parents[1] / "data"
DOCKERHUB_FILE = DATA_DIR / "dockerhub_dockerfiles.jsonl"

DOCKERHUB_BASE = "https://hub.docker.com/v2"
GH_BASE = "https://api.github.com"

# ─── Official Docker Library repos ───────────────────────────────────────────
OFFICIAL_LIBRARY_REPO = "docker-library"

# Top official Docker Hub images with their GitHub source repos
OFFICIAL_IMAGES = {
    # Language runtimes
    "python": "docker-library/python",
    "node": "docker-library/node",
    "golang": "docker-library/golang",
    "ruby": "docker-library/ruby",
    "java": "docker-library/openjdk",
    "openjdk": "docker-library/openjdk",
    "php": "docker-library/php",
    "rust": "docker-library/rust",

    # Databases
    "postgres": "docker-library/postgres",
    "mysql": "docker-library/mysql",
    "redis": "docker-library/redis",
    "mongo": "docker-library/mongo",
    "mariadb": "docker-library/mariadb",
    "elasticsearch": "elastic/elasticsearch",
    "cassandra": "docker-library/cassandra",
    "couchdb": "apache/couchdb-docker",

    # Web servers
    "nginx": "nginxinc/docker-nginx",
    "apache": "docker-library/httpd",
    "haproxy": "docker-library/haproxy",
    "traefik": "traefik/traefik-library-image",

    # Base OS images
    "ubuntu": "docker-library/ubuntu",
    "debian": "docker-library/debian",
    "alpine": "alpinelinux/docker-alpine",
    "centos": "docker-library/centos",
    "fedora": "docker-library/fedora",
    "amazonlinux": "amazonlinux/amazon-linux-docker",

    # Tools
    "jenkins": "jenkinsci/docker",
    "gitlab": "sameersbn/docker-gitlab",
    "grafana": "grafana/grafana",
    "prometheus": "prometheus/prometheus",
    "sonarqube": "SonarSource/docker-sonarqube",
    "vault": "docker-library/vault",
    "consul": "hashicorp/docker-consul",

    # ML/Data
    "tensorflow": "tensorflow/tensorflow",
    "pytorch": "pytorch/pytorch",
    "jupyter": "jupyter/docker-stacks",
}

# ─── Dockerfile security analysis patterns ────────────────────────────────────

# Patterns that indicate unpinned/risky Dockerfile practices
SECURITY_ISSUES = {
    "unpinned_base_image": re.compile(r'^FROM\s+(\w[\w/.-]+):(latest|stable|lts)\s*$', re.MULTILINE | re.I),
    "root_user": re.compile(r'^USER\s+root\s*$', re.MULTILINE | re.I),
    "no_user_set": None,  # checked separately
    "curl_piped_to_sh": re.compile(r'curl\s+.*\|\s*(bash|sh)', re.I),
    "wget_piped_to_sh": re.compile(r'wget\s+.*\|\s*(bash|sh)', re.I),
    "apt_no_pinning": re.compile(r'apt-get\s+install\s+(?!.*=\s*\d)', re.I),
    "pip_no_pinning": re.compile(r'pip\s+install\s+(?!.*==)(?!.*-r\s)', re.I),
    "npm_audit_skip": re.compile(r'npm\s+install\s+.*--no-audit', re.I),
    "secrets_in_env": re.compile(r'ENV\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*\S+', re.I),
    "secrets_in_arg": re.compile(r'ARG\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*\S+', re.I),
    "sudo_usage": re.compile(r'\bsudo\b', re.I),
    "add_instead_of_copy": re.compile(r'^ADD\s+(?!https?://)', re.MULTILINE | re.I),
    "privileged_cap": re.compile(r'--privileged|--cap-add\s*SYS_ADMIN', re.I),
    "outdated_openssl": re.compile(r'openssl[<>=!]+1\.[01]\.\d', re.I),
}

# Labels for what makes a good vs bad Dockerfile
GOOD_PRACTICES = {
    "pinned_base_image": re.compile(r'^FROM\s+[\w/.-]+:(\d[\d.]+)(@sha256:[a-f0-9]+)?\s*$', re.MULTILINE),
    "non_root_user": re.compile(r'^USER\s+(?!root)\w+', re.MULTILINE),
    "multi_stage_build": re.compile(r'^FROM\s+.*\s+AS\s+\w+', re.MULTILINE | re.I),
    "healthcheck": re.compile(r'^HEALTHCHECK\b', re.MULTILINE | re.I),
    "pinned_apt": re.compile(r'apt-get\s+install\s+.*=\s*\d', re.I),
    "pinned_pip": re.compile(r'pip\s+install\s+[\w-]+==[0-9.]+', re.I),
    "no_secrets_baked_in": None,  # checked separately
    "layer_optimization": re.compile(r'&&\s*\\?\s*\n', re.I),  # chained RUN commands
}


def dh_get(endpoint: str, params: dict = None) -> dict:
    """Make Docker Hub API request."""
    url = f"{DOCKERHUB_BASE}/{endpoint}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "sealpatch-scanner/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def gh_get(endpoint: str, params: dict, token: str = "") -> dict:
    """Make GitHub API request."""
    url = f"{GH_BASE}/{endpoint}?" + urllib.parse.urlencode(params)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "sealpatch-scanner/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def fetch_image_tags(image_name: str, max_tags: int = 10) -> list[dict]:
    """Fetch tags for a Docker Hub image."""
    data = dh_get(f"repositories/library/{image_name}/tags", {
        "page_size": max_tags,
        "ordering": "last_updated",
    })
    return data.get("results", [])


def fetch_dockerfile_from_github(
    repo: str,
    image_name: str,
    tag: str,
    token: str,
) -> Optional[str]:
    """Fetch Dockerfile from GitHub for an official Docker image."""
    # Try common paths
    paths_to_try = [
        f"{tag}/Dockerfile",
        f"{tag}/linux/amd64/Dockerfile",
        f"Dockerfile",
        f"{image_name}/Dockerfile",
        f"latest/Dockerfile",
    ]

    parts = repo.split("/")
    if len(parts) != 2:
        return None
    owner, repo_name = parts

    for path in paths_to_try:
        url = f"https://raw.githubusercontent.com/{owner}/{repo_name}/master/{path}"
        req = urllib.request.Request(url, headers={"User-Agent": "sealpatch-scanner/1.0"})
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode("utf-8", errors="replace")
                if "FROM" in content and len(content) > 50:
                    return content
        except Exception:
            continue

    # Try fetching repo contents to find Dockerfiles
    contents = gh_get(f"repos/{owner}/{repo_name}/contents", {}, token)
    if isinstance(contents, list):
        for item in contents:
            if item.get("name") == "Dockerfile" or item.get("name", "").endswith("Dockerfile"):
                dl_url = item.get("download_url", "")
                if dl_url:
                    req = urllib.request.Request(dl_url, headers={"User-Agent": "sealpatch-scanner/1.0"})
                    try:
                        with urllib.request.urlopen(req, timeout=10) as resp:
                            return resp.read().decode("utf-8", errors="replace")
                    except Exception:
                        pass

    return None


def analyze_dockerfile(dockerfile: str, image_name: str) -> dict:
    """
    Analyze a Dockerfile for security issues and good practices.
    Returns a structured analysis with issue descriptions.
    """
    issues = []
    good_practices_found = []

    # Check security issues
    for issue_name, pattern in SECURITY_ISSUES.items():
        if pattern is None:
            continue
        if pattern.search(dockerfile):
            severity = "HIGH" if issue_name in (
                "curl_piped_to_sh", "wget_piped_to_sh",
                "secrets_in_env", "secrets_in_arg",
            ) else "MEDIUM"
            issues.append({
                "issue": issue_name,
                "severity": severity,
                "description": _get_issue_description(issue_name),
            })

    # Check for no USER instruction (runs as root by default)
    if not re.search(r'^USER\s+\w+', dockerfile, re.MULTILINE):
        issues.append({
            "issue": "no_user_set",
            "severity": "MEDIUM",
            "description": "No USER instruction: container runs as root by default",
        })

    # Check good practices
    for practice_name, pattern in GOOD_PRACTICES.items():
        if pattern is None:
            continue
        if pattern.search(dockerfile):
            good_practices_found.append(practice_name)

    # Compute a severity-weighted security score (0-10, higher = better)
    # HIGH issues cost 2 points each, MEDIUM issues cost 1 point each
    penalty = sum(2 if i["severity"] == "HIGH" else 1 for i in issues)
    security_score = max(0, 10 - penalty)

    return {
        "issues": issues,
        "issue_count": len(issues),
        "good_practices": good_practices_found,
        "security_score": security_score,
        "has_high_severity": any(i["severity"] == "HIGH" for i in issues),
    }


def _get_issue_description(issue_name: str) -> str:
    """Return human-readable description for a Dockerfile issue."""
    descriptions = {
        "unpinned_base_image": "Base image uses :latest tag - pin to a specific version for reproducibility",
        "root_user": "Container runs as root - add a non-root USER instruction",
        "no_user_set": "No USER instruction - container runs as root by default",
        "curl_piped_to_sh": "Piping curl output to shell is a security risk - verify checksums instead",
        "wget_piped_to_sh": "Piping wget output to shell is a security risk",
        "apt_no_pinning": "apt-get install without version pinning - versions may drift",
        "pip_no_pinning": "pip install without version pinning - use pip install package==version",
        "npm_audit_skip": "npm install with --no-audit skips security checks",
        "secrets_in_env": "Secret/password in ENV instruction will be visible in image layers",
        "secrets_in_arg": "Secret in ARG instruction may be visible in build history",
        "sudo_usage": "sudo in Dockerfile is unusual - consider running as appropriate user",
        "add_instead_of_copy": "COPY is preferred over ADD for local files (ADD has implicit tar extraction)",
        "privileged_cap": "Privileged mode or dangerous capabilities increases attack surface",
        "outdated_openssl": "OpenSSL 1.0/1.1 has known vulnerabilities - upgrade to 3.x",
    }
    return descriptions.get(issue_name, f"Security issue: {issue_name}")


def generate_patch_suggestion(dockerfile: str, analysis: dict) -> str:
    """Generate a patched Dockerfile that addresses the identified issues."""
    patched = dockerfile

    for issue in analysis["issues"]:
        issue_name = issue["issue"]

        if issue_name == "unpinned_base_image":
            # Replace :latest with a note (can't determine correct version automatically)
            patched = re.sub(
                r'^(FROM\s+[\w/.-]+):latest\s*$',
                r'\1:REPLACE_WITH_SPECIFIC_VERSION  # Pin to specific version, e.g., :3.11-slim',
                patched, flags=re.MULTILINE | re.I,
            )
        elif issue_name == "no_user_set":
            # Add USER instruction before CMD/ENTRYPOINT
            patched = re.sub(
                r'^(CMD|ENTRYPOINT)\b',
                r'# Add non-root user for security\nRUN groupadd -r appuser && useradd -r -g appuser appuser\nUSER appuser\n\n\1',
                patched, count=1, flags=re.MULTILINE,
            )

    return patched


def build_training_record(
    image_name: str,
    tag: str,
    dockerfile: str,
    analysis: dict,
    repo: str,
) -> dict:
    """Build a (dockerfile_with_issues, issues_found) training record."""
    patched = generate_patch_suggestion(dockerfile, analysis)

    issue_summaries = [
        f"- [{i['severity']}] {i['description']}"
        for i in analysis["issues"]
    ]
    issues_text = "\n".join(issue_summaries) if issue_summaries else "No significant issues found"

    return {
        "type": "dockerfile_analysis",
        "image_name": image_name,
        "tag": tag,
        "github_repo": repo,
        "dockerfile": dockerfile[:5000],
        "patched_dockerfile": patched[:5000],
        "analysis": analysis,
        "issues_summary": issues_text,
        "security_score": analysis["security_score"],
        "has_issues": len(analysis["issues"]) > 0,
        "training_input": f"Analyze this Dockerfile for security issues:\n\n```dockerfile\n{dockerfile[:3000]}\n```",
        "training_output": f"Security analysis for {image_name}:{tag}:\n\n{issues_text}\n\nSecurity score: {analysis['security_score']}/10",
    }


def save_records(records: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DOCKERHUB_FILE, "a") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Scan Docker Hub official images for Dockerfile security issues"
    )
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--official-only", action="store_true",
                        help="Only process official Docker images (default)")
    parser.add_argument("--max-images", type=int, default=200)
    parser.add_argument("--max-tags-per-image", type=int, default=5)
    args = parser.parse_args()

    print(f"=== DOCKER HUB SCANNER ===")
    print(f"Images to scan: {min(len(OFFICIAL_IMAGES), args.max_images)}")

    total_records = 0
    images_processed = 0

    for image_name, gh_repo in list(OFFICIAL_IMAGES.items())[:args.max_images]:
        print(f"\n  Scanning: {image_name} (source: {gh_repo})")

        # Fetch tags to know which versions exist
        tags = fetch_image_tags(image_name, args.max_tags_per_image)
        time.sleep(0.2)

        records_for_image = []
        for tag_info in tags[:3]:  # limit to 3 tags per image
            tag = tag_info.get("name", "latest")
            if not tag:
                continue

            dockerfile = fetch_dockerfile_from_github(gh_repo, image_name, tag, args.token)
            time.sleep(0.2)

            if not dockerfile:
                continue

            analysis = analyze_dockerfile(dockerfile, image_name)
            record = build_training_record(image_name, tag, dockerfile, analysis, gh_repo)
            records_for_image.append(record)

        save_records(records_for_image)
        total_records += len(records_for_image)
        images_processed += 1

        issue_counts = [r["analysis"]["issue_count"] for r in records_for_image]
        avg_issues = sum(issue_counts) / len(issue_counts) if issue_counts else 0
        print(f"    {len(records_for_image)} Dockerfiles analyzed | avg issues: {avg_issues:.1f}")

        time.sleep(0.3)

    print(f"\n=== DONE ===")
    print(f"Images scanned: {images_processed}")
    print(f"Dockerfile records: {total_records}")
    print(f"Output: {DOCKERHUB_FILE}")


if __name__ == "__main__":
    main()
