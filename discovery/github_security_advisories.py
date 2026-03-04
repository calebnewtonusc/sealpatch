"""
github_security_advisories.py - GitHub Advisory Database patch PR discovery.

Uses the GitHub Advisory Database API to find security advisories and the
corresponding patch PRs, extracting (vulnerable_code, cve_id, patch_diff) triples.

API: https://api.github.com/advisories
Docs: https://docs.github.com/en/rest/security-advisories/global-advisories

Usage:
    export GITHUB_TOKEN=your_token
    python discovery/github_security_advisories.py
    python discovery/github_security_advisories.py --ecosystem npm
    python discovery/github_security_advisories.py --severity critical
"""

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

DATA_DIR = Path(__file__).parents[1] / "data"
GHSA_FILE = DATA_DIR / "github_security_advisories.jsonl"
PATCH_DIFFS_FILE = DATA_DIR / "ghsa_patch_diffs.jsonl"
GHSA_PROGRESS_FILE = DATA_DIR / "ghsa_progress.json"

GH_BASE = "https://api.github.com"

ECOSYSTEMS = [
    "pip", "npm", "go", "maven", "rubygems",
    "cargo", "nuget", "composer", "swift", "pub",
]

SEVERITY_FILTER = {
    "critical": ["critical"],
    "high": ["critical", "high"],
    "medium": ["critical", "high", "medium"],
    "all": ["critical", "high", "medium", "low"],
}


def gh_get(endpoint: str, params: dict, token: str) -> dict:
    """Make authenticated GitHub API request."""
    url = f"{GH_BASE}/{endpoint}?" + urllib.parse.urlencode(params)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sealpatch-ghsa-harvester/1.0",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    except Exception as e:
        if hasattr(e, 'code') and e.code == 403:
            time.sleep(15)
        return {}


def gh_get_list(endpoint: str, params: dict, token: str) -> list:
    result = gh_get(endpoint, params, token)
    if isinstance(result, list):
        return result
    return []


def fetch_advisories_page(
    token: str,
    ecosystem: str = None,
    severity: str = None,
    page: int = 1,
    per_page: int = 100,
) -> list[dict]:
    """Fetch a page of GitHub security advisories."""
    params = {
        "type": "reviewed",
        "per_page": per_page,
        "page": page,
    }
    if ecosystem:
        params["ecosystem"] = ecosystem
    if severity:
        params["severity"] = severity

    result = gh_get_list("advisories", params, token)
    return result if isinstance(result, list) else []


def search_patch_prs(
    owner: str,
    repo: str,
    cve_id: str,
    ghsa_id: str,
    package_name: str,
    token: str,
) -> list[dict]:
    """
    Search for PRs in a repo that fix a specific CVE/GHSA.
    These are the security patch PRs we want to train on.
    """
    prs = []

    # Search strategies
    search_queries = [
        f"repo:{owner}/{repo} {cve_id} in:title is:pr",
        f"repo:{owner}/{repo} {ghsa_id} in:title is:pr",
        f"repo:{owner}/{repo} security fix {package_name} in:title is:merged is:pr",
        f"repo:{owner}/{repo} bump {package_name} security is:merged is:pr",
    ]

    for query in search_queries[:2]:  # limit queries to avoid rate limit
        data = gh_get("search/issues", {"q": query, "per_page": 10}, token)
        items = data.get("items", [])
        for item in items:
            if "pull_request" in item:
                prs.append({
                    "number": item.get("number"),
                    "title": item.get("title"),
                    "url": item.get("html_url"),
                    "state": item.get("state"),
                    "merged": item.get("pull_request", {}).get("merged_at") is not None,
                })
        time.sleep(0.5)

    return prs[:5]  # cap at 5 PRs per advisory


def get_pr_diff(owner: str, repo: str, pr_number: int, token: str) -> str:
    """Get the diff for a pull request."""
    url = f"{GH_BASE}/repos/{owner}/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.diff",  # Get diff format
        "User-Agent": "sealpatch-ghsa-harvester/1.0",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="replace")[:10000]
    except Exception:
        return ""


def get_pr_files(owner: str, repo: str, pr_number: int, token: str) -> list[dict]:
    """Get files changed in a PR."""
    files = gh_get_list(
        f"repos/{owner}/{repo}/pulls/{pr_number}/files",
        {"per_page": 50},
        token,
    )
    return [
        {
            "filename": f.get("filename", ""),
            "status": f.get("status", ""),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
            "patch": (f.get("patch") or "")[:3000],
        }
        for f in files[:20]
    ]


def extract_package_vulnerabilities(advisory: dict) -> list[dict]:
    """Extract package vulnerability records from an advisory."""
    records = []
    ghsa_id = advisory.get("ghsa_id", "")
    cve_id = advisory.get("cve_id", "")
    summary = advisory.get("summary", "")[:500]
    description = advisory.get("description", "")[:1000]
    severity = advisory.get("severity", "UNKNOWN").upper()
    cvss = advisory.get("cvss", {})
    cvss_score = cvss.get("score", 0.0) if isinstance(cvss, dict) else 0.0

    for vuln in advisory.get("vulnerabilities", []):
        pkg = vuln.get("package", {})
        ecosystem = pkg.get("ecosystem", "unknown")
        package_name = pkg.get("name", "")

        if not package_name:
            continue

        vulnerable_range = vuln.get("vulnerable_version_range", "")
        patched_versions = vuln.get("patched_versions", "")
        first_patched = (vuln.get("first_patched_version") or {}).get("identifier", "")

        # Build training description
        patch_instruction = ""
        if patched_versions or first_patched:
            fixed = first_patched or patched_versions
            patch_instruction = f"Upgrade {package_name} to {fixed} or later"

        # Build Dockerfile-specific fix suggestion
        dockerfile_fix = _build_dockerfile_fix(ecosystem, package_name, first_patched or patched_versions)

        records.append({
            "type": "ghsa_vulnerability",
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "ecosystem": ecosystem,
            "package_name": package_name,
            "vulnerable_version_range": vulnerable_range,
            "patched_versions": patched_versions,
            "first_patched_version": first_patched,
            "severity": severity,
            "cvss_score": cvss_score,
            "summary": summary,
            "description": description,
            "patch_instruction": patch_instruction,
            "dockerfile_fix": dockerfile_fix,
            "published_at": advisory.get("published_at", ""),
            "updated_at": advisory.get("updated_at", ""),
            "references": [r.get("url") for r in advisory.get("references", [])[:5]],
            "identifiers": advisory.get("identifiers", []),
        })

    return records


def _build_dockerfile_fix(ecosystem: str, package_name: str, fixed_version: str) -> str:
    """Build a Dockerfile-specific fix instruction."""
    if not fixed_version:
        return f"Upgrade {package_name} to the latest patched version"

    eco = ecosystem.lower()
    if eco == "pip":
        return f"In requirements.txt or Dockerfile: {package_name}>={fixed_version}"
    elif eco == "npm":
        return f"In package.json: \"{package_name}\": \">={fixed_version}\""
    elif eco == "maven":
        return (f"In pom.xml: <version>{fixed_version}</version> "
                f"for groupId containing {package_name}")
    elif eco == "go":
        return f"In go.mod: require {package_name} v{fixed_version}"
    elif eco == "cargo":
        return f"In Cargo.toml: {package_name} = \">={fixed_version}\""
    elif eco in ("debian", "ubuntu", "alpine"):
        return f"In Dockerfile: RUN apt-get install -y {package_name}={fixed_version}"
    else:
        return f"Upgrade {package_name} to >= {fixed_version}"


def find_and_extract_patch_diff(
    advisory: dict,
    vuln_records: list[dict],
    token: str,
) -> list[dict]:
    """
    Find patch PRs for an advisory and extract diffs.
    Returns list of (vulnerable_code, cve_id, patch_diff) records.
    """
    patch_records = []
    ghsa_id = advisory.get("ghsa_id", "")
    cve_id = advisory.get("cve_id", "")

    # Look in references for PRs
    references = advisory.get("references", [])
    pr_urls = [r.get("url", "") for r in references
               if "pull" in r.get("url", "") and "github.com" in r.get("url", "")]

    for pr_url in pr_urls[:3]:  # limit to 3 PRs per advisory
        # Parse owner/repo/number from URL
        # https://github.com/owner/repo/pull/123
        parts = pr_url.replace("https://github.com/", "").split("/")
        if len(parts) < 4 or parts[2] != "pull":
            continue

        owner, repo, _, pr_number_str = parts[:4]
        try:
            pr_number = int(pr_number_str.split("#")[0].split("?")[0])
        except ValueError:
            continue

        # Get diff
        diff = get_pr_diff(owner, repo, pr_number, token)
        if not diff:
            continue

        files = get_pr_files(owner, repo, pr_number, token)
        time.sleep(0.2)

        # Filter to security-relevant files
        sec_files = [f for f in files if any(
            kw in f["filename"].lower()
            for kw in ["requirement", "package.json", "package-lock", "cargo.toml",
                        "pom.xml", "gemfile", "go.mod", "dockerfile"]
        )]

        # Use the first vuln_rec only (not a cross-product of PRs × vuln_records)
        vuln_rec = vuln_records[0] if vuln_records else {}
        patch_records.append({
            "type": "patch_diff",
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "package_name": vuln_rec.get("package_name"),
            "ecosystem": vuln_rec.get("ecosystem"),
            "vulnerable_version_range": vuln_rec.get("vulnerable_version_range"),
            "first_patched_version": vuln_rec.get("first_patched_version"),
            "pr_url": pr_url,
            "pr_number": pr_number,
            "repo": f"{owner}/{repo}",
            "diff_preview": diff[:5000],
            "security_files_changed": sec_files,
            "training_triple": {
                "vulnerability": f"{cve_id or ghsa_id}: {vuln_rec.get('summary', '')}",
                "package": vuln_rec.get("package_name"),
                "patch_instruction": vuln_rec.get("patch_instruction"),
                "dockerfile_fix": vuln_rec.get("dockerfile_fix"),
            },
        })

    return patch_records


def save_records(records: list[dict], filepath: Path) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def load_progress() -> dict:
    if GHSA_PROGRESS_FILE.exists():
        return json.loads(GHSA_PROGRESS_FILE.read_text())
    return {"completed_ecosystems": [], "total_advisories": 0, "total_diffs": 0}


def save_progress(progress: dict) -> None:
    GHSA_PROGRESS_FILE.write_text(json.dumps(progress))


def main():
    parser = argparse.ArgumentParser(
        description="Harvest GitHub Security Advisories for SealPatch training"
    )
    parser.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--ecosystem", type=str, default=None,
                        help="Specific ecosystem (pip, npm, go, maven, etc.)")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "all"],
                        default="all")
    parser.add_argument("--extract-diffs", action="store_true",
                        help="Also extract patch diffs from referenced PRs")
    parser.add_argument("--max-pages", type=int, default=50)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    if not args.token:
        print("Error: GITHUB_TOKEN required")
        return

    progress = load_progress() if args.resume else {"completed_ecosystems": [], "total_advisories": 0, "total_diffs": 0}

    ecosystems_to_process = [args.ecosystem] if args.ecosystem else ECOSYSTEMS
    severity_list = SEVERITY_FILTER.get(args.severity, SEVERITY_FILTER["all"])

    print(f"=== GITHUB ADVISORY HARVESTER ===")
    print(f"Ecosystems: {ecosystems_to_process}")
    print(f"Severity: {args.severity}")

    total_advisories = progress.get("total_advisories", 0)
    total_diffs = progress.get("total_diffs", 0)

    for ecosystem in ecosystems_to_process:
        if ecosystem in progress.get("completed_ecosystems", []):
            print(f"  [skip] {ecosystem}")
            continue

        print(f"\n  Processing ecosystem: {ecosystem}")
        eco_count = 0

        for severity in severity_list[:2]:  # process top 2 severity levels
            page = 1
            while page <= args.max_pages:
                advisories = fetch_advisories_page(
                    args.token, ecosystem=ecosystem, severity=severity,
                    page=page, per_page=100,
                )
                if not advisories:
                    break

                vuln_batch = []
                diff_batch = []

                for advisory in advisories:
                    vuln_records = extract_package_vulnerabilities(advisory)
                    vuln_batch.extend(vuln_records)

                    if args.extract_diffs and vuln_records:
                        diffs = find_and_extract_patch_diff(advisory, vuln_records, args.token)
                        diff_batch.extend(diffs)
                        time.sleep(0.3)

                save_records(vuln_batch, GHSA_FILE)
                if diff_batch:
                    save_records(diff_batch, PATCH_DIFFS_FILE)

                total_advisories += len(vuln_batch)
                total_diffs += len(diff_batch)
                eco_count += len(advisories)

                print(f"    {ecosystem}/{severity} page {page}: +{len(vuln_batch)} vulns, +{len(diff_batch)} diffs")

                if len(advisories) < 100:
                    break
                page += 1
                time.sleep(0.5)

        progress["completed_ecosystems"] = progress.get("completed_ecosystems", []) + [ecosystem]
        progress["total_advisories"] = total_advisories
        progress["total_diffs"] = total_diffs
        save_progress(progress)
        print(f"  {ecosystem}: {eco_count} advisories processed")

    print(f"\n=== SUMMARY ===")
    print(f"Total vulnerability records: {total_advisories}")
    print(f"Total patch diffs: {total_diffs}")
    print(f"Outputs: {GHSA_FILE}, {PATCH_DIFFS_FILE}")


if __name__ == "__main__":
    main()
