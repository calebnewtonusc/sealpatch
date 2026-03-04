# SealPatch — Data Sources

## Overview

SealPatch trains on CVE-fix pairs: the before-and-after of security remediations, paired with CVE scan outputs and CI outcomes. Every time a developer fixes a CVE in a Dockerfile or lockfile and CI stays green, that's a training example. We collect 400,000+ such pairs.

**Total target**: 400,000+ (scan_results, artifact, fix_diff, ci_outcome) tuples

---

## Stream 1: CVE Remediation Commits (35% — ~140k pairs)

**What**: GitHub commits that explicitly fix CVEs, paired with before/after Grype scan results.

**How**:
1. GitHub search: `"fix CVE" OR "patch CVE" OR "update.*security" OR "bump.*vuln"` in commit messages
2. For each matching commit, fetch the parent commit (before) and the commit itself (after)
3. Collect changed files: Dockerfiles, `*.txt` (requirements), `*.json` (package.json/lock), `*.toml`, `go.mod`, `Gemfile.lock`
4. Run Grype on both before and after states
5. Include pair only if after-state has strictly fewer CRITICAL/HIGH CVEs
6. Fetch CI outcome for the fix commit (must be green)

**Sources**: Top 20,000 GitHub repos with Dockerfiles (by stars). Focus on language: Python, Node, Go, Java.

**Collection script**: `discovery/dockerfile_crawler.py`

**Estimated pairs**: 140,000 (after quality filter)

---

## Stream 2: OSV/NVD/GitHub Advisory Corpus (25% — ~100k pairs)

**What**: CVE advisories synthesized into (vulnerability_context, fix_strategy) pairs.

**How**:
1. Sync OSV database (osv.dev API) — all security advisories with affected/fixed versions
2. Sync NVD (NIST) — CVSS scores, affected packages, fix versions
3. Sync GitHub Advisory Database (GHSA) — ecosystem-specific (npm, pip, Go, Maven, RubyGems, Cargo)
4. For each advisory: extract affected package + version range + fixed version + CVSS vector
5. Use LLM to synthesize: "What does a Dockerfile/lockfile with this CVE look like?" + "What's the minimal fix?"

**Coverage**:
- OSV: 60,000+ advisories across 17 ecosystems
- NVD: 200,000+ CVEs (filter to those with package-level fix information)
- GHSA: 15,000+ ecosystem-specific advisories

**Collection script**: `discovery/cve_database.py`

**Estimated pairs**: 100,000

---

## Stream 3: Snyk/Dependabot Security PRs (20% — ~80k pairs)

**What**: Security-focused PRs (Snyk bot, Dependabot security updates) that passed CI.

**How**:
1. GitHub search: `author:snyk-bot OR author:dependabot[bot] label:security is:pr is:merged`
2. For each PR: fetch before/after lockfile state + CI outcome
3. Run Grype on before/after images (for Docker PRs)
4. Include only PRs where CI was green after merge (behavior preserved)
5. Label with CVE categories using NVD/OSV lookup

**Coverage**: Python, npm, Go, Maven, Cargo, RubyGems ecosystems

**Key insight from this stream**: Snyk and Dependabot generate many "bump everything" PRs. The DPO training stage specifically uses this data to teach SealPatch to prefer *surgical* fixes over blanket upgrades.

**Estimated pairs**: 80,000

---

## Stream 4: Container Image Update History (12% — ~48k pairs)

**What**: Historical Docker Hub image scan results showing CVE count reduction after version bumps.

**How**:
1. Scrape Docker Hub for popular base images: `ubuntu`, `debian`, `alpine`, `python`, `node`, `golang`, `openjdk`, `ruby`
2. For each image, collect all available tags (versions) and their scan dates
3. Run Grype on sequential tag pairs (e.g., `ubuntu:22.04-20240101` → `ubuntu:22.04-20240301`)
4. Include pairs where the newer tag has fewer CRITICAL/HIGH CVEs
5. Label: which CVEs were removed, what OS packages changed

**Special focus**: Alpine image updates (alpine changes image content aggressively, good training signal).

**Estimated pairs**: 48,000

---

## Stream 5: Synthesized CVE-Fix Pairs (8% — ~32k pairs)

**What**: LLM-synthesized Dockerfiles with injected CVEs + corresponding minimal fixes.

**How**:
1. Start from real Dockerfiles (Stream 1 corpus)
2. Inject CVE-affected package versions (from OSV/NVD data)
3. Generate expected Grype scan output for the injected artifact
4. Use LLM to generate the minimal fix
5. **Validation**: Build the Dockerfile, run Grype on the image, confirm CVE is actually present in "before", absent in "after"

**Coverage goals**: Underrepresented scenarios (Java/Maven CVEs, Cargo/Rust CVEs, multi-stage builds, distroless images).

**Estimated pairs**: 32,000 (after sandbox validation filtering ~60% acceptance rate)

---

## Data Quality Pipeline

All pairs pass through 6-step quality filter:

1. **CVE verification**: Before-state artifact must actually contain the CVE being fixed (Grype confirmation)
2. **Fix effectiveness**: After-state must have fewer CRITICAL/HIGH CVEs than before (minimum 1 fewer)
3. **CI validation**: Fix commit must have green CI in the source repo
4. **Diff sanity**: Fix diff must be <200 lines and apply cleanly
5. **Category labeling**: CVE category must be confirmed by NVD/OSV lookup
6. **MinHash dedup**: 85% Jaccard similarity threshold

**Expected retention rate**: ~60% of raw pairs

---

## Data Schema

```json
{
  "id": "sealpatch_django_repo_a1b2c3",
  "source": "remediation_commit",
  "repo": "owner/repo",
  "language": "python",
  "ci_platform": "github_actions",
  "before_sha": "abc123",
  "fix_sha": "def456",
  "dockerfile_before": "FROM python:3.11-slim\nRUN pip install requests==2.28.0\n...",
  "dockerfile_after": "FROM python:3.11-slim\nRUN pip install requests==2.31.0\n...",
  "scan_before": {
    "critical": 1,
    "high": 3,
    "medium": 12,
    "cves": ["CVE-2023-32681"]
  },
  "scan_after": {
    "critical": 0,
    "high": 0,
    "medium": 12,
    "cves": []
  },
  "fix_diff": "--- a/requirements.txt\n+++ b/requirements.txt\n@@ -1 +1 @@\n-requests==2.28.0\n+requests==2.31.0\n",
  "cve_categories": ["APP_DEP_CVE"],
  "cves_fixed": ["CVE-2023-32681"],
  "ci_outcome": "green",
  "behavior_preserved": true,
  "pr_count": 1,
  "verified_scan": true
}
```
