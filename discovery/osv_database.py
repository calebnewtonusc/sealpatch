"""
osv_database.py - OSV (Open Source Vulnerabilities) database sync for SealPatch.

OSV is more complete than NVD for package-level vulnerabilities.
Covers: npm, PyPI, Maven, Go, Cargo, RubyGems, NuGet, Composer, etc.

Creates (package@version, vulnerability, fixed_version) records.

OSV API: https://api.osv.dev/v1/
Docs: https://google.github.io/osv.dev/api/

Usage:
    python discovery/osv_database.py
    python discovery/osv_database.py --ecosystems npm pip cargo
    python discovery/osv_database.py --severity critical high
"""

import argparse
import json
import time
import urllib.request
import urllib.parse
from pathlib import Path

DATA_DIR = Path(__file__).parents[1] / "data"
OSV_FILE = DATA_DIR / "osv_vulnerabilities.jsonl"
OSV_PROGRESS_FILE = DATA_DIR / "osv_progress.json"

OSV_BASE = "https://api.osv.dev/v1"

# ─── Ecosystems to sync ────────────────────────────────────────────────────────
ALL_ECOSYSTEMS = [
    "PyPI",  # Python packages
    "npm",  # Node.js packages
    "Go",  # Go modules
    "Maven",  # Java packages
    "crates.io",  # Rust packages
    "RubyGems",  # Ruby gems
    "NuGet",  # .NET packages
    "Packagist",  # PHP/Composer packages
    "Hex",  # Elixir packages
    "Pub",  # Dart/Flutter packages
    "SwiftURL",  # Swift packages
    "Debian",  # Debian packages (apt)
    "Alpine",  # Alpine packages (apk)
    "Ubuntu",  # Ubuntu packages
    "Linux",  # Linux kernel
]

# Ecosystems most relevant to container security
CONTAINER_ECOSYSTEMS = [
    "PyPI",
    "npm",
    "Go",
    "Maven",
    "crates.io",
    "RubyGems",
    "Debian",
    "Alpine",
    "Ubuntu",
]

# ─── CVE severity keywords for filtering ─────────────────────────────────────
SEVERITY_LEVELS = {
    "critical": ["CRITICAL"],
    "high": ["CRITICAL", "HIGH"],
    "medium": ["CRITICAL", "HIGH", "MEDIUM"],
    "all": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
}


def osv_query(ecosystem: str, page_token: str = None) -> dict:
    """Query OSV API for a given ecosystem."""
    payload = {
        "ecosystem": ecosystem,
        "page_size": 500,
    }
    if page_token:
        payload["page_token"] = page_token

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{OSV_BASE}/query",
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "sealpatch-osv-harvester/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"    [ERROR] OSV query {ecosystem}: {e}")
        return {}


def osv_get_vuln(osv_id: str) -> dict:
    """Get full vulnerability details by OSV ID."""
    req = urllib.request.Request(
        f"{OSV_BASE}/vulns/{osv_id}",
        headers={"User-Agent": "sealpatch-osv-harvester/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def extract_version_ranges(affected_entry: dict) -> list[dict]:
    """Extract version ranges from an OSV affected entry."""
    ranges = []
    for r in affected_entry.get("ranges", []):
        range_type = r.get("type", "SEMVER")
        events = r.get("events", [])

        introduced = None
        fixed = None
        last_affected = None

        for event in events:
            if "introduced" in event:
                introduced = event["introduced"]
            if "fixed" in event:
                fixed = event["fixed"]
            if "last_affected" in event:
                last_affected = event["last_affected"]

        ranges.append(
            {
                "type": range_type,
                "introduced": introduced,
                "fixed": fixed,
                "last_affected": last_affected,
            }
        )
    return ranges


def extract_specific_versions(affected_entry: dict) -> list[str]:
    """Extract explicitly listed affected versions."""
    return affected_entry.get("versions", [])[:50]  # cap at 50


def build_osv_record(vuln: dict, ecosystem: str) -> list[dict]:
    """
    Build training records from an OSV vulnerability.
    Creates one record per affected package in the vulnerability.
    """
    records = []
    osv_id = vuln.get("id", "")
    summary = vuln.get("summary", "")[:500]
    details = vuln.get("details", "")[:1000]
    severity = vuln.get("database_specific", {}).get("severity", "UNKNOWN")
    cve_aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE-")]
    published = vuln.get("published", "")
    modified = vuln.get("modified", "")

    # Extract severity from OSV structured severity field
    cvss_score = 0.0
    for entry in vuln.get("severity", []):
        if entry.get("type") in ("CVSS_V3", "CVSS_V2"):
            # OSV severity entries may carry a numeric score directly
            raw_score = entry.get("score", "")
            try:
                cvss_score = float(raw_score)
                break
            except (ValueError, TypeError):
                pass
        # Also check database_specific for severity mapping
    if cvss_score == 0.0:
        db_specific = vuln.get("database_specific", {})
        sev_str = db_specific.get("severity", "").upper()
        if sev_str == "CRITICAL":
            cvss_score = 9.5
        elif sev_str == "HIGH":
            cvss_score = 7.5
        elif sev_str == "MEDIUM":
            cvss_score = 5.0
        elif sev_str == "LOW":
            cvss_score = 2.5

    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        pkg_name = pkg.get("name", "")
        pkg_ecosystem = pkg.get("ecosystem", ecosystem)

        if not pkg_name:
            continue

        version_ranges = extract_version_ranges(affected)
        specific_versions = extract_specific_versions(affected)

        # Find the fixed version (first "fixed" in any range)
        fixed_version = None
        for vr in version_ranges:
            if vr.get("fixed"):
                fixed_version = vr["fixed"]
                break

        # Build the training record
        # Key fields: what package, what versions are vulnerable, what fixes it
        training_description_parts = [
            f"Vulnerability {osv_id} in {pkg_ecosystem} package {pkg_name}",
        ]
        if cve_aliases:
            training_description_parts.append(
                f"CVE aliases: {', '.join(cve_aliases[:3])}"
            )
        if summary:
            training_description_parts.append(f"Summary: {summary}")
        if fixed_version:
            training_description_parts.append(f"Fixed in version: {fixed_version}")
        if specific_versions:
            training_description_parts.append(
                f"Known affected versions: {', '.join(specific_versions[:5])}"
            )

        record = {
            "type": "osv_vulnerability",
            "osv_id": osv_id,
            "ecosystem": pkg_ecosystem,
            "package_name": pkg_name,
            "cve_ids": cve_aliases[:5],
            "summary": summary,
            "details": details,
            "severity": severity,
            "cvss_score": cvss_score,
            "version_ranges": version_ranges,
            "specific_affected_versions": specific_versions[:20],
            "fixed_version": fixed_version,
            "published": published,
            "modified": modified,
            "training_description": ". ".join(training_description_parts),
            # Patch instruction for Dockerfile/requirements.txt
            "patch_instruction": (
                f"Upgrade {pkg_name} to {fixed_version} or later to fix {osv_id}"
                if fixed_version
                else f"Package {pkg_name} is affected by {osv_id} - check for updates"
            ),
        }
        records.append(record)

    return records


def load_progress() -> dict:
    if OSV_PROGRESS_FILE.exists():
        return json.loads(OSV_PROGRESS_FILE.read_text())
    return {"completed_ecosystems": [], "total_saved": 0}


def save_progress(completed: list[str], total: int) -> None:
    OSV_PROGRESS_FILE.write_text(
        json.dumps({"completed_ecosystems": completed, "total_saved": total})
    )


def save_records(records: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OSV_FILE, "a") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Sync OSV vulnerability database for SealPatch training"
    )
    parser.add_argument(
        "--ecosystems",
        nargs="+",
        default=CONTAINER_ECOSYSTEMS,
        help="Ecosystems to sync",
    )
    parser.add_argument(
        "--all-ecosystems",
        action="store_true",
        help="Sync ALL ecosystems (including Debian, Alpine, etc.)",
    )
    parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "all"],
        default="all",
        help="Minimum severity to include",
    )
    parser.add_argument("--max-per-ecosystem", type=int, default=50000)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    if args.all_ecosystems:
        ecosystems = ALL_ECOSYSTEMS
    else:
        ecosystems = args.ecosystems

    severity_filter = set(SEVERITY_LEVELS.get(args.severity, SEVERITY_LEVELS["all"]))

    progress = (
        load_progress()
        if args.resume
        else {"completed_ecosystems": [], "total_saved": 0}
    )
    completed = progress.get("completed_ecosystems", [])
    total_saved = progress.get("total_saved", 0)

    print("=== OSV DATABASE SYNC ===")
    print(f"Ecosystems: {ecosystems}")
    print(f"Severity filter: {args.severity}")
    print(f"Already completed: {completed}\n")

    for ecosystem in ecosystems:
        if ecosystem in completed:
            print(f"  [skip] {ecosystem} (already done)")
            continue

        print(f"\n  Syncing {ecosystem}...")
        page_token = None
        ecosystem_count = 0
        page = 0

        while ecosystem_count < args.max_per_ecosystem:
            data = osv_query(ecosystem, page_token)
            vulns = data.get("vulns", [])
            if not vulns:
                break

            records = []
            for vuln in vulns:
                # Severity filter
                sev = (
                    vuln.get("database_specific", {}).get("severity") or "UNKNOWN"
                ).upper()
                if sev not in severity_filter and "UNKNOWN" not in severity_filter:
                    continue
                new_records = build_osv_record(vuln, ecosystem)
                records.extend(new_records)

            save_records(records)
            total_saved += len(records)
            ecosystem_count += len(vulns)
            page += 1

            page_token = data.get("next_page_token")
            print(
                f"    Page {page}: +{len(records)} records | ecosystem total: {ecosystem_count} | overall: {total_saved}"
            )

            if not page_token:
                break
            time.sleep(0.2)

        completed.append(ecosystem)
        save_progress(completed, total_saved)
        print(f"  {ecosystem} complete: {ecosystem_count} vulns processed")

    print("\n=== OSV SYNC COMPLETE ===")
    print(f"Total vulnerability records saved: {total_saved}")
    print(f"Output: {OSV_FILE}")


if __name__ == "__main__":
    main()
