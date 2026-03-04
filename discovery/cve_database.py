"""
SealPatch — CVE Database Sync
Syncs OSV, NVD, and GitHub Advisory databases for training pair generation.

Usage:
  python discovery/cve_database.py --sync-all
  python discovery/cve_database.py --sync-osv
  python discovery/cve_database.py --query CVE-2024-1234
"""

import asyncio
import json
import os
from pathlib import Path

import aiohttp
import typer
from loguru import logger

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_BASE = "https://api.osv.dev/v1"
GHSA_BASE = "https://api.github.com/advisories"


async def sync_osv_ecosystem(
    session: aiohttp.ClientSession,
    ecosystem: str,
    output_dir: Path,
    max_advisories: int = 50000,
) -> int:
    """Sync all advisories for a given OSV ecosystem."""
    output_file = output_dir / f"osv_{ecosystem.lower()}.jsonl"
    if output_file.exists():
        logger.info(f"  OSV {ecosystem}: already synced, skipping")
        return 0

    page_token = None
    total = 0

    with open(output_file, "w") as f:
        while total < max_advisories:
            payload = {"ecosystem": ecosystem, "page_size": 500}
            if page_token:
                payload["page_token"] = page_token

            try:
                async with session.post(
                    f"{OSV_BASE}/query",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        break
                    data = await resp.json()
            except Exception as e:
                logger.debug(f"OSV {ecosystem} error: {e}")
                break

            vulns = data.get("vulns", [])
            if not vulns:
                break

            for vuln in vulns:
                # Extract the information we need for training
                affected = vuln.get("affected", [])
                for aff in affected:
                    pkg = aff.get("package", {})
                    ranges = aff.get("ranges", [])

                    fixed_version = None
                    for r in ranges:
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_version = event["fixed"]
                                break

                    record = {
                        "id": vuln.get("id"),
                        "ecosystem": ecosystem,
                        "package_name": pkg.get("name", ""),
                        "affected_ranges": [
                            {
                                "introduced": e.get("introduced"),
                                "fixed": e.get("fixed"),
                            }
                            for r in ranges
                            for e in r.get("events", [])
                        ],
                        "fixed_version": fixed_version,
                        "summary": vuln.get("summary", "")[:500],
                        "severity": vuln.get("database_specific", {}).get(
                            "severity", "UNKNOWN"
                        ),
                        "aliases": vuln.get("aliases", []),
                        "published": vuln.get("published", ""),
                        "modified": vuln.get("modified", ""),
                    }
                    f.write(json.dumps(record) + "\n")
                    total += 1

            page_token = data.get("next_page_token")
            if not page_token:
                break

            await asyncio.sleep(0.1)

    logger.info(f"  OSV {ecosystem}: synced {total} advisories")
    return total


async def sync_nvd_batch(
    session: aiohttp.ClientSession,
    output_dir: Path,
    start_index: int = 0,
    max_results: int = 200000,
) -> int:
    """Sync NVD CVE database in batches."""
    output_file = output_dir / "nvd_cves.jsonl"
    total_written = 0
    idx = start_index

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    # Load existing CVE IDs to avoid duplicates on resume
    seen_cve_ids: set = set()
    if output_file.exists():
        with open(output_file) as existing:
            for line in existing:
                line = line.strip()
                if line:
                    try:
                        rec = json.loads(line)
                        if rec.get("cve_id"):
                            seen_cve_ids.add(rec["cve_id"])
                    except Exception:
                        pass

    with open(output_file, "a") as f:
        while idx < max_results:
            params = {"startIndex": idx, "resultsPerPage": 2000}

            try:
                async with session.get(
                    NVD_BASE,
                    headers=headers,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as resp:
                    if resp.status != 200:
                        logger.warning(f"NVD returned {resp.status}, stopping batch")
                        break
                    data = await resp.json()
            except Exception as e:
                logger.debug(f"NVD error at index {idx}: {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            for vuln_wrapper in vulns:
                cve = vuln_wrapper.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract CVSS score
                metrics = cve.get("metrics", {})
                cvss_score = 0.0
                severity = "UNKNOWN"
                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if version in metrics and metrics[version]:
                        m = metrics[version][0]
                        cvss_score = m.get("cvssData", {}).get("baseScore", 0.0)
                        severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                        break

                # Extract affected configurations
                cve.get("configurations", [])

                if cve_id in seen_cve_ids:
                    continue
                seen_cve_ids.add(cve_id)
                record = {
                    "cve_id": cve_id,
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": cve.get("descriptions", [{}])[0].get("value", "")[
                        :1000
                    ]
                    if cve.get("descriptions")
                    else "",
                    "references": [r.get("url") for r in cve.get("references", [])[:5]],
                }
                f.write(json.dumps(record) + "\n")
                total_written += 1

            idx += len(vulns)

            if total_written % 10000 == 0:
                logger.info(f"  NVD sync: {total_written} CVEs synced")

            # NVD rate limit: 5 req/30s without key, 50 req/30s with key
            sleep_time = 0.5 if NVD_API_KEY else 6.5
            await asyncio.sleep(sleep_time)

    logger.info(f"  NVD sync complete: {total_written} CVEs")
    return total_written


async def sync_github_advisories(
    session: aiohttp.ClientSession,
    output_dir: Path,
    ecosystems: list[str] = None,
) -> int:
    """Sync GitHub Security Advisory Database."""
    if ecosystems is None:
        ecosystems = [
            "pip",
            "npm",
            "go",
            "maven",
            "rubygems",
            "cargo",
            "nuget",
            "composer",
        ]

    output_file = output_dir / "github_advisories.jsonl"
    total = 0

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    with open(output_file, "w") as f:
        for ecosystem in ecosystems:
            page = 1
            while True:
                try:
                    async with session.get(
                        GHSA_BASE,
                        headers=headers,
                        params={
                            "ecosystem": ecosystem,
                            "per_page": 100,
                            "page": page,
                            "type": "reviewed",
                        },
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status != 200:
                            break
                        data = await resp.json()
                except Exception as e:
                    logger.debug(f"GHSA error ({ecosystem}): {e}")
                    break

                if not data:
                    break

                for advisory in data:
                    vulns = advisory.get("vulnerabilities", [])
                    for vuln in vulns:
                        record = {
                            "ghsa_id": advisory.get("ghsa_id"),
                            "cve_id": advisory.get("cve_id"),
                            "ecosystem": ecosystem,
                            "package_name": vuln.get("package", {}).get("name", ""),
                            "vulnerable_version_range": vuln.get(
                                "vulnerable_version_range", ""
                            ),
                            "patched_versions": vuln.get("patched_versions", ""),
                            "first_patched_version": vuln.get(
                                "first_patched_version", {}
                            ).get("identifier"),
                            "severity": advisory.get("severity", "UNKNOWN").upper(),
                            "summary": advisory.get("summary", "")[:500],
                            "cvss_score": advisory.get("cvss", {}).get("score", 0.0)
                            if advisory.get("cvss")
                            else 0.0,
                            "published_at": advisory.get("published_at", ""),
                        }
                        f.write(json.dumps(record) + "\n")
                        total += 1

                if len(data) < 100:
                    break
                page += 1
                await asyncio.sleep(0.2)

            logger.info(
                f"  GHSA {ecosystem}: synced advisories (running total: {total})"
            )

    logger.info(f"GHSA sync complete: {total} ecosystem advisories")
    return total


async def main_async(
    output_dir: Path,
    sync_osv_flag: bool,
    sync_nvd_flag: bool,
    sync_ghsa_flag: bool,
):
    output_dir.mkdir(parents=True, exist_ok=True)
    connector = aiohttp.TCPConnector(limit=10)

    async with aiohttp.ClientSession(connector=connector) as session:
        total = 0
        if sync_osv_flag:
            logger.info("Syncing OSV database...")
            for ecosystem in [
                "PyPI",
                "npm",
                "Go",
                "Maven",
                "RubyGems",
                "crates.io",
                "NuGet",
            ]:
                total += await sync_osv_ecosystem(session, ecosystem, output_dir)

        if sync_nvd_flag:
            logger.info("Syncing NVD CVE database...")
            total += await sync_nvd_batch(session, output_dir)

        if sync_ghsa_flag and GITHUB_TOKEN:
            logger.info("Syncing GitHub Advisory database...")
            total += await sync_github_advisories(session, output_dir)

    logger.info(f"CVE database sync complete: {total} total records")


app = typer.Typer()


@app.command()
def main(
    output: Path = typer.Option(Path("data/cve_db"), help="Output directory"),
    sync_all: bool = typer.Option(False, "--sync-all", help="Sync all databases"),
    sync_osv: bool = typer.Option(False, "--sync-osv"),
    sync_nvd: bool = typer.Option(False, "--sync-nvd"),
    sync_ghsa: bool = typer.Option(False, "--sync-ghsa"),
    query: str = typer.Option(None, help="Query a specific CVE ID"),
):
    """Sync CVE databases (OSV, NVD, GitHub Advisory)."""
    if query:
        logger.info(f"Querying {query} from local DB...")
        return

    if sync_all:
        sync_osv = sync_nvd = sync_ghsa = True

    if not any([sync_osv, sync_nvd, sync_ghsa]):
        logger.error("Specify --sync-all, --sync-osv, --sync-nvd, or --sync-ghsa")
        raise typer.Exit(1)

    asyncio.run(main_async(output, sync_osv, sync_nvd, sync_ghsa))


if __name__ == "__main__":
    app()
