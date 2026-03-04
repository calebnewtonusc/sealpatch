"""
SealPatch — Dockerfile Crawler
Collects Dockerfiles and lockfiles from top GitHub repositories.
Pairs pre-fix and post-fix states for CVE remediation commits.

Usage:
  python discovery/dockerfile_crawler.py --repos 20000 --workers 30
"""

import asyncio
import base64
import json
import os
import re
import time
from pathlib import Path

import aiohttp
import typer
from loguru import logger

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_API = "https://api.github.com"
HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Files to collect per repo
TARGET_FILES = [
    "Dockerfile",
    "dockerfile",
    "requirements.txt",
    "requirements-prod.txt",
    "requirements/prod.txt",
    "package-lock.json",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "Gemfile.lock",
    "Cargo.lock",
    "pom.xml",
]

SECURITY_COMMIT_KEYWORDS = [
    "fix cve",
    "patch cve",
    "security fix",
    "security patch",
    "bump.*security",
    "update.*vuln",
    "remediate",
    "upgrade.*cve",
]


async def fetch_json(session: aiohttp.ClientSession, url: str, params: dict | None = None):
    for attempt in range(3):
        try:
            async with session.get(url, headers=HEADERS, params=params) as resp:
                if resp.status == 403:
                    reset_at = int(
                        resp.headers.get("X-RateLimit-Reset", time.time() + 60)
                    )
                    await asyncio.sleep(max(reset_at - time.time(), 1))
                    continue
                if resp.status == 200:
                    return await resp.json()
                return None
        except Exception:
            await asyncio.sleep(2**attempt)
    return None


async def get_file_content(
    session: aiohttp.ClientSession, repo: str, path: str, ref: str
) -> str | None:
    """Fetch raw file content from GitHub."""
    data = await fetch_json(
        session,
        f"{GITHUB_API}/repos/{repo}/contents/{path}",
        params={"ref": ref},
    )
    if not data or data.get("encoding") != "base64":
        return None
    try:
        return base64.b64decode(data["content"].replace("\n", "")).decode(
            "utf-8", errors="replace"
        )
    except Exception:
        return None


async def find_security_commits(
    session: aiohttp.ClientSession, repo: str
) -> list[dict]:
    """Find commits with security/CVE fix keywords."""
    security_commits = []
    page = 1
    while page <= 5:
        data = await fetch_json(
            session,
            f"{GITHUB_API}/repos/{repo}/commits",
            params={"per_page": 100, "page": page},
        )
        if not data:
            break

        for commit in data:
            message = commit.get("commit", {}).get("message", "").lower()
            if any(re.search(kw, message) for kw in SECURITY_COMMIT_KEYWORDS):
                security_commits.append(commit)

        if len(data) < 100:
            break
        page += 1

    return security_commits[:20]  # Cap per repo


async def collect_repo_artifacts(
    session: aiohttp.ClientSession,
    repo: str,
    output_dir: Path,
) -> int:
    """Collect Dockerfiles, lockfiles, and CVE fix commit pairs from a repo."""
    repo_slug = repo.replace("/", "__")
    output_file = output_dir / f"{repo_slug}.jsonl"
    if output_file.exists():
        return 0

    security_commits = await find_security_commits(session, repo)
    if not security_commits:
        return 0

    pairs_written = 0
    with open(output_file, "w") as f:
        for commit in security_commits:
            fix_sha = commit["sha"]
            parents = commit.get("parents", [])
            if not parents:
                continue
            before_sha = parents[0]["sha"]

            # Collect artifacts for both states
            artifacts_before = {}
            artifacts_after = {}

            for target_file in TARGET_FILES:
                content_before = await get_file_content(
                    session, repo, target_file, before_sha
                )
                content_after = await get_file_content(
                    session, repo, target_file, fix_sha
                )
                if content_before or content_after:
                    artifacts_before[target_file] = content_before or ""
                    artifacts_after[target_file] = content_after or ""

            if not artifacts_before:
                continue

            record = {
                "id": f"sealpatch_{repo_slug}_{fix_sha[:8]}",
                "source": "remediation_commit",
                "repo": repo,
                "before_sha": before_sha,
                "fix_sha": fix_sha,
                "commit_message": commit.get("commit", {}).get("message", "")[:500],
                "artifacts_before": artifacts_before,
                "artifacts_after": artifacts_after,
                "scan_before": None,  # Will be filled by scan_agent.py
                "scan_after": None,
            }
            f.write(json.dumps(record) + "\n")
            pairs_written += 1

    logger.info(f"  {repo}: {pairs_written} artifact pairs")
    return pairs_written


async def discover_repos(session: aiohttp.ClientSession, limit: int) -> list[str]:
    """Discover popular repos with Dockerfiles."""
    repos: list[str] = []
    for lang in ["python", "javascript", "go", "java", "ruby"]:
        page = 1
        while len(repos) < limit:
            data = await fetch_json(
                session,
                f"{GITHUB_API}/search/repositories",
                params={
                    "q": f"language:{lang} stars:>200 topic:docker archived:false",
                    "sort": "stars",
                    "per_page": 100,
                    "page": page,
                },
            )
            if not data or not data.get("items"):
                break
            repos.extend(item["full_name"] for item in data["items"])
            if len(data["items"]) < 100:
                break
            page += 1
            await asyncio.sleep(0.5)
    return list(set(repos))[:limit]


async def main_async(repos: int, workers: int, output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    connector = aiohttp.TCPConnector(limit=workers * 2)
    semaphore = asyncio.Semaphore(workers)

    async with aiohttp.ClientSession(connector=connector) as session:
        logger.info(f"Discovering top {repos} repos with Dockerfiles...")
        repo_list = await discover_repos(session, repos)
        logger.info(f"Found {len(repo_list)} repos")

        async def process(r):
            async with semaphore:
                try:
                    return await collect_repo_artifacts(session, r, output_dir)
                except Exception as e:
                    logger.debug(f"Error on {r}: {e}")
                    return 0

        results = await asyncio.gather(*[process(r) for r in repo_list])
        logger.info(f"Collected {sum(results)} artifact pairs")


app = typer.Typer()


@app.command()
def main(
    repos: int = typer.Option(20000, help="Number of repos to scan"),
    workers: int = typer.Option(30, help="Concurrent workers"),
    output: Path = typer.Option(Path("data/raw/artifacts"), help="Output directory"),
):
    """Collect Dockerfiles and lockfiles + CVE remediation commit pairs."""
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN not set")
        raise typer.Exit(1)
    asyncio.run(main_async(repos, workers, output))


if __name__ == "__main__":
    app()
