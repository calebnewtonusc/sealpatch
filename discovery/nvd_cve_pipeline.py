"""
nvd_cve_pipeline.py - NVD CVE data pipeline for container/package vulnerability training.

Pulls ALL CVEs from NVD API 2.0 and filters to container/package-relevant ones.
For each CVE, finds affected package versions + patched versions.
Links CVEs to affected Dockerfiles via GitHub search.

Target: 100k+ (vulnerable_package, cve_id, patched_version) triples.

NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
NVD Docs: https://nvd.nist.gov/developers/vulnerabilities

Usage:
    export NVD_API_KEY=your_key  # optional, higher rate limit
    export GITHUB_TOKEN=your_token  # for Dockerfile search
    python discovery/nvd_cve_pipeline.py --sync
    python discovery/nvd_cve_pipeline.py --sync --filter-container
    python discovery/nvd_cve_pipeline.py --link-dockerfiles
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
NVD_FILE = DATA_DIR / "nvd_container_cves.jsonl"
DOCKERFILE_LINKS_FILE = DATA_DIR / "cve_dockerfile_links.jsonl"

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH_BASE = "https://api.github.com"

# ─── Container/package CVE filter criteria ───────────────────────────────────
# CWE IDs most relevant to container/package vulnerabilities
CONTAINER_CWES = {
    "CWE-1035",  # OWASP: Using Components with Known Vulnerabilities
    "CWE-1104",  # Use of Unmaintained Third Party Components
    "CWE-20",  # Improper Input Validation
    "CWE-22",  # Path Traversal
    "CWE-78",  # OS Command Injection
    "CWE-79",  # XSS (relevant in npm packages)
    "CWE-89",  # SQL Injection (npm/pip)
    "CWE-94",  # Code Injection
    "CWE-502",  # Deserialization
    "CWE-400",  # Resource Exhaustion
    "CWE-918",  # SSRF
    "CWE-611",  # XXE
    "CWE-915",  # Improperly Controlled Modification of Dynamically-Determined Object
}

# Keywords indicating a package/dependency CVE (not kernel/hardware)
PACKAGE_CVE_KEYWORDS = [
    "npm",
    "pypi",
    "pip",
    "rubygems",
    "maven",
    "gradle",
    "cargo",
    "crates.io",
    "docker",
    "container",
    "apt",
    "dpkg",
    "package",
    "dependency",
    "library",
    "node.js",
    "python",
    "ruby",
    "java",
    "golang",
    "rust",
    "perl",
    "php",
    "nginx",
    "apache",
    "openssl",
    "curl",
    "libssl",
    "libcurl",
    "log4j",
    "log4shell",
    "spring",
    "jackson",
    "struts",
]

# Well-known package CVEs with definitive patch information
HIGH_VALUE_CVES = {
    "CVE-2021-44228": {"package": "log4j", "fixed": "2.15.0", "ecosystem": "maven"},
    "CVE-2021-45046": {"package": "log4j", "fixed": "2.16.0", "ecosystem": "maven"},
    "CVE-2022-22965": {
        "package": "spring-webmvc",
        "fixed": "5.3.18",
        "ecosystem": "maven",
    },
    "CVE-2022-42889": {
        "package": "commons-text",
        "fixed": "1.10.0",
        "ecosystem": "maven",
    },
    "CVE-2021-42574": {"package": "various", "fixed": "N/A", "ecosystem": "unicode"},
    "CVE-2021-43138": {"package": "async", "fixed": "3.2.2", "ecosystem": "npm"},
    "CVE-2022-25858": {"package": "terser", "fixed": "5.14.2", "ecosystem": "npm"},
    "CVE-2021-23337": {"package": "lodash", "fixed": "4.17.21", "ecosystem": "npm"},
    "CVE-2022-37434": {"package": "zlib", "fixed": "1.2.13", "ecosystem": "apt"},
    "CVE-2023-44487": {"package": "nghttp2", "fixed": "1.57.0", "ecosystem": "apt"},
}


def nvd_get(start_index: int, results_per_page: int, api_key: str = "") -> dict:
    """Make NVD API request with optional API key."""
    params = {
        "startIndex": start_index,
        "resultsPerPage": min(results_per_page, 2000),
    }
    url = f"{NVD_BASE}?" + urllib.parse.urlencode(params)
    headers = {"User-Agent": "sealpatch-nvd-harvester/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"    [ERROR] NVD request at {start_index}: {e}")
        return {}


def is_container_package_cve(cve: dict) -> bool:
    """
    Heuristically determine if a CVE is relevant to container/package security.
    Filters out firmware, hardware, and unrelated kernel CVEs.
    """
    descriptions = cve.get("descriptions", [])
    desc_text = " ".join(d.get("value", "") for d in descriptions).lower()

    # Check for package keywords
    if any(kw in desc_text for kw in PACKAGE_CVE_KEYWORDS):
        return True

    # Check CWE IDs
    weaknesses = cve.get("weaknesses", [])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc.get("value", "") in CONTAINER_CWES:
                return True

    # Check references for package registries
    references = cve.get("references", [])
    ref_urls = [r.get("url", "") for r in references]
    registry_patterns = [
        "npmjs.com",
        "pypi.org",
        "rubygems.org",
        "mvnrepository",
        "crates.io",
        "pkg.go.dev",
        "hub.docker.com",
    ]
    if any(any(reg in url for reg in registry_patterns) for url in ref_urls):
        return True

    return False


def extract_affected_packages(cve: dict) -> list[dict]:
    """
    Extract affected package/version information from NVD CVE data.
    Returns list of {package_name, vendor, affected_versions, cpe_string}.
    """
    affected = []
    configs = cve.get("configurations", [])

    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue

                cpe = cpe_match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) < 6:
                    continue

                vendor = parts[3]
                product = parts[4]
                version = parts[5]

                version_start = cpe_match.get("versionStartIncluding", "")
                version_end_incl = cpe_match.get("versionEndIncluding", "")
                version_end_excl = cpe_match.get("versionEndExcluding", "")

                # versionEndExcluding is the first FIXED version
                fixed_version = version_end_excl if version_end_excl else None

                affected.append(
                    {
                        "vendor": vendor,
                        "product": product,
                        "version_range_start": version_start or version,
                        "version_range_end_including": version_end_incl,
                        "version_range_end_excluding": version_end_excl,
                        "fixed_version": fixed_version,
                        "cpe": cpe,
                    }
                )

    return affected


def extract_cvss_scores(cve: dict) -> dict:
    """Extract CVSS scores from CVE metrics."""
    metrics = cve.get("metrics", {})
    result = {"cvss_score": 0.0, "severity": "UNKNOWN", "vector": ""}

    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if version in metrics and metrics[version]:
            m = metrics[version][0]
            cvss_data = m.get("cvssData", {})
            result["cvss_score"] = cvss_data.get("baseScore", 0.0)
            result["severity"] = cvss_data.get("baseSeverity", "UNKNOWN")
            result["vector"] = cvss_data.get("vectorString", "")
            break

    return result


def build_cve_record(vuln_wrapper: dict) -> Optional[dict]:
    """Build a training record from an NVD CVE wrapper."""
    cve = vuln_wrapper.get("cve", {})
    cve_id = cve.get("id", "")

    if not is_container_package_cve(cve):
        return None

    descriptions = cve.get("descriptions", [])
    desc_en = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
    )

    cvss = extract_cvss_scores(cve)
    affected_packages = extract_affected_packages(cve)

    # Check if this is a high-value known CVE
    high_value_info = HIGH_VALUE_CVES.get(cve_id, {})

    # Build Dockerfile patch scenario description
    patch_scenarios = []
    for pkg in affected_packages[:5]:  # limit to top 5 per CVE
        if pkg.get("fixed_version"):
            patch_scenarios.append(
                f"Package {pkg['product']} needs upgrade from "
                f"{pkg['version_range_start'] or 'affected version'} to "
                f"{pkg['fixed_version']} to fix {cve_id}"
            )

    return {
        "cve_id": cve_id,
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "description": desc_en[:800],
        "cvss_score": cvss["cvss_score"],
        "severity": cvss["severity"],
        "cvss_vector": cvss["vector"],
        "affected_packages": affected_packages[:20],
        "patch_scenarios": patch_scenarios,
        "references": [r.get("url") for r in cve.get("references", [])[:5]],
        "cwe_ids": [
            d.get("value")
            for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
        ],
        "is_high_value": cve_id in HIGH_VALUE_CVES,
        "high_value_info": high_value_info,
    }


def search_dockerfiles_for_cve(
    cve_id: str,
    packages: list[dict],
    gh_token: str,
) -> list[dict]:
    """
    Search GitHub for Dockerfiles that use vulnerable package versions.
    """
    if not gh_token or not packages:
        return []

    results = []
    # Use the first affected package to search
    pkg = packages[0]
    product = pkg.get("product", "")
    if not product:
        return []

    # Search for Dockerfiles mentioning this package
    query = f"filename:Dockerfile {product} in:file"
    url = f"{GH_BASE}/search/code?" + urllib.parse.urlencode(
        {
            "q": query,
            "per_page": 10,
        }
    )
    headers = {
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "sealpatch-nvd-harvester/1.0",
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
            for item in data.get("items", [])[:5]:
                results.append(
                    {
                        "cve_id": cve_id,
                        "package": product,
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "file_path": item.get("path", ""),
                        "url": item.get("html_url", ""),
                    }
                )
    except Exception:
        pass

    time.sleep(1.0)  # GitHub code search is strict on rate limits
    return results


def load_progress() -> dict:
    progress_file = DATA_DIR / "nvd_progress.json"
    if progress_file.exists():
        return json.loads(progress_file.read_text())
    return {"last_index": 0, "total_saved": 0}


def save_progress(index: int, total: int) -> None:
    progress_file = DATA_DIR / "nvd_progress.json"
    progress_file.write_text(json.dumps({"last_index": index, "total_saved": total}))


def save_records(records: list[dict], filepath: Path) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "a") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Sync NVD CVE database for SealPatch training data"
    )
    parser.add_argument("--sync", action="store_true", help="Sync CVEs from NVD")
    parser.add_argument(
        "--filter-container",
        action="store_true",
        help="Filter to container/package CVEs only (default behavior)",
    )
    parser.add_argument(
        "--link-dockerfiles",
        action="store_true",
        help="Link CVEs to affected Dockerfiles on GitHub",
    )
    parser.add_argument("--nvd-key", default=os.environ.get("NVD_API_KEY", ""))
    parser.add_argument("--gh-token", default=os.environ.get("GITHUB_TOKEN", ""))
    parser.add_argument("--max-cves", type=int, default=300000)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    if not args.sync and not args.link_dockerfiles:
        print("Specify --sync and/or --link-dockerfiles")
        return

    if args.sync:
        progress = (
            load_progress() if args.resume else {"last_index": 0, "total_saved": 0}
        )
        start_index = progress["last_index"]
        total_saved = progress["total_saved"]

        # Rate limits: 5 req/30s without key, 50 req/30s with key
        sleep_time = 0.7 if args.nvd_key else 7.0

        print("=== NVD CVE PIPELINE ===")
        print(f"Starting at index {start_index}")
        print(
            f"API key present: {'yes' if args.nvd_key else 'no (slower rate limit)'}\n"
        )

        idx = start_index
        while idx < args.max_cves:
            data = nvd_get(idx, 2000, args.nvd_key)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                print(f"  [STOP] No more CVEs at index {idx}")
                break

            total_results = data.get("totalResults", 0)
            records = []
            for v in vulns:
                rec = build_cve_record(v)
                if rec:
                    records.append(rec)

            save_records(records, NVD_FILE)
            total_saved += len(records)
            idx += len(vulns)

            print(
                f"  Index {idx:>7}/{total_results} | +{len(records)} container CVEs | total: {total_saved}"
            )
            save_progress(idx, total_saved)

            if len(vulns) < 2000:
                print("  [DONE] All CVEs retrieved")
                break

            time.sleep(
                sleep_time
            )  # Rate limit: skip on last page (already broke above)

        print(f"\nNVD sync complete: {total_saved} container/package CVEs saved")
        print(f"Output: {NVD_FILE}")

    if args.link_dockerfiles:
        print("\n=== LINKING CVES TO DOCKERFILES ===")
        if not args.gh_token:
            print("Warning: no GITHUB_TOKEN, skipping Dockerfile linking")
            return

        cves = []
        if NVD_FILE.exists():
            with open(NVD_FILE) as f:
                for line in f:
                    try:
                        cves.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        # Prioritize high-value CVEs and CRITICAL severity
        cves.sort(
            key=lambda c: (c.get("is_high_value", False), c.get("cvss_score", 0)),
            reverse=True,
        )

        total_links = 0
        for cve in cves[:1000]:  # Limit to top 1000 for Dockerfile search
            cve_id = cve.get("cve_id", "")
            affected = cve.get("affected_packages", [])
            links = search_dockerfiles_for_cve(cve_id, affected, args.gh_token)
            if links:
                save_records(links, DOCKERFILE_LINKS_FILE)
                total_links += len(links)
                print(
                    f"  {cve_id}: {len(links)} Dockerfile links (total: {total_links})"
                )
            time.sleep(0.5)

        print(f"\nDockerfile links saved: {total_links}")
        print(f"Output: {DOCKERFILE_LINKS_FILE}")


if __name__ == "__main__":
    main()
