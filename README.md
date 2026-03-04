# SealPatch

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Model: Qwen2.5-7B-Coder](https://img.shields.io/badge/base_model-Qwen2.5--7B--Coder-purple.svg)](https://huggingface.co/Qwen)
[![GPUs: 18x A6000](https://img.shields.io/badge/training-18×_A6000-red.svg)](https://www.nvidia.com)
[![Status: Training](https://img.shields.io/badge/status-training-orange.svg)]()

> **"Scanners report. SealPatch removes."**

SealPatch is the first trained specialist model for CVE remediation. The gap in the security market isn't detection — every team already has Grype, Trivy, Snyk, and Dependabot firing alerts. The gap is *safe, behavior-preserving remediation*. SealPatch takes a scan report with 240 CVEs and produces 3-5 minimal PRs that eliminate all of them without breaking your application.

This repository contains the complete dataset pipeline, training infrastructure, and deployment stack for SealPatch — from raw CVE database sync to a production-ready remediation agent.

---

## The Problem SealPatch Solves

Security scanners are very good at finding CVEs. They are not good at fixing them. When a scanner reports:

```
CRITICAL: CVE-2024-1234 in libssl 1.1.1q
HIGH: CVE-2024-5678 in node:18.12-alpine
MEDIUM: 238 additional findings
```

What do you do next? Options:

1. **Manually research each CVE** — 240 hours of work, most engineers skip this
2. **Bump all deps** — often breaks the app, causes downstream CI failures
3. **Ignore it** — the most common "choice"

SealPatch does what a skilled security engineer would do: understand which CVEs matter (base image vs. app layer, exploitable vs. theoretical), identify the minimal set of changes that eliminate all high-severity findings, validate that behavior is preserved, and open PRs with full remediation rationale.

---

## Why SealPatch Is Different

| Capability | Snyk | Dependabot | OWASP Dep-Check | Manual Triage | **SealPatch** |
|---|---|---|---|---|---|
| Finds CVEs | yes | yes | yes | manual | **yes (via Grype/Trivy integration)** |
| Generates fix PRs | yes | yes | — | — | **yes** |
| Understands base image vs. app layer | — | — | — | expert only | **trained distinction** |
| Validates behavior preserved (CI green) | — | — | — | manual | **sandbox CI validation** |
| Prioritizes CVEs by exploitability | partial | — | — | manual | **CVSS + reachability** |
| Handles transitive dep cascades | — | partial | — | expert only | **full dep graph analysis** |
| Dev-only CVE suppression | manual | — | — | manual | **automatic** |
| Groups CVEs into minimal PRs | — | 1 per dep | — | — | **batched by root cause** |

---

## Architecture

```
                  ┌────────────────────────────────────────────────────────┐
 Dockerfile /     │                  SealPatch System                      │
 lockfiles /   ──►│                                                        │
 scan results     │  ┌─────────────────────────────────────────────────┐  │
                  │  │            SealPatch Model                      │  │
                  │  │  (Qwen2.5-7B-Coder + LoRA rank 64              │  │
                  │  │   SFT → GRPO → DPO, ZeRO-3 trained)            │  │
                  │  └──────────────────┬──────────────────────────────┘  │
                  │                     │                                  │
                  │         ┌───────────▼───────────┐                     │
                  │         │    Scan Agent          │                     │
                  │         │  (Grype + Trivy)       │                     │
                  │         └───────────┬───────────┘                     │
                  │                     │                                  │
                  │         ┌───────────▼───────────┐                     │
                  │         │   CVE Prioritizer      │                     │
                  │         │  CRITICAL → HIGH →     │                     │
                  │         │  MEDIUM (dev-only ✗)   │                     │
                  │         └───────────┬───────────┘                     │
                  │                     │                                  │
                  │         ┌───────────▼───────────┐                     │
                  │         │    Patch Agent         │                     │
                  │         │  (grouped by root)     │                     │
                  │         └───────────┬───────────┘                     │
                  │                     │                                  │
                  │         ┌───────────▼───────────┐                     │
                  │         │  Validation Agent      │                     │
                  │         │  CI sandbox smoke test │                     │
                  │         └───────────┬───────────┘                     │
                  │                     │                                  │
                  │         ┌───────────▼───────────┐                     │
                  │         │    PR Generator        │                     │
                  │         │  (1 PR per CVE batch)  │                     │
                  │         └───────────────────────┘                     │
                  └────────────────────────────────────────────────────────┘
```

**Training data sources (5 streams, 400k+ CVE→fix pairs):**
- Stream 1: Public CVE remediation commits — Dockerfile + lockfile fixes (35%)
- Stream 2: OSV/NVD/GitHub Advisory corpus — CVE metadata + affected versions (25%)
- Stream 3: Snyk/Dependabot PRs with CI outcome — successful remediations only (20%)
- Stream 4: Container image update history — base image version + scan outcome deltas (12%)
- Stream 5: Synthesized CVE-fix pairs with sandbox validation (8%)

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/calebnewtonusc/sealpatch
cd sealpatch
pip install -r requirements.txt
cp .env.example .env  # Fill in API keys

# Verify environment
bash scripts/check_env.sh

# Run on a repository right now (no training required — uses base model)
python agents/scan_agent.py --repo owner/repo --github-token $GITHUB_TOKEN

# Run full pipeline (data → training → eval), ~38 hours on 18× A6000
bash scripts/run_all.sh
```

### Scan and Patch a Repository

```bash
# Full scan + patch + PR generation
python agents/patch_agent.py \
  --repo owner/repo \
  --github-token $GITHUB_TOKEN \
  --min-severity HIGH \
  --open-prs

# Or use the REST API
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo": "owner/repo", "min_severity": "HIGH", "open_prs": true}'
```

---

## SealBench Results (Target v1)

| Metric | Target | Snyk | Dependabot |
|--------|--------|------|------------|
| CVE elimination rate (500 scenarios) | >80% | ~60% | ~45% |
| Behavior preserved (CI green after fix) | >95% | ~70% | ~80% |
| False positive PR rate | <5% | ~15% | ~10% |
| Avg PRs per repo (minimality) | <4 | ~20 | ~50 |
| CRITICAL/HIGH CVE elimination rate | >90% | ~75% | ~55% |
| Dev-only CVE suppression accuracy | >85% | ~40% | — |

---

## Hardware Requirements

| Stage | Config | Estimated Time |
|-------|--------|----------------|
| Discovery (CVE sync + repo scan) | CPU, internet | 6-8 hours |
| Synthesis (vLLM) | 4× A6000 per instance | 12-14 hours |
| SFT Training | 18× A6000, ZeRO-3 | 7 hours |
| GRPO Training | 18× A6000 + sandbox | 4 hours |
| DPO Training | 18× A6000 | 2 hours |
| Inference (production) | 1× A6000 | <5s per scan |

---

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — Full technical architecture and CVE taxonomy
- [DATA_SOURCES.md](DATA_SOURCES.md) — 5 training data streams
- [MODEL_CARD.md](MODEL_CARD.md) — Model specification and limitations
- [ROADMAP.md](ROADMAP.md) — v1 through v3 roadmap
- [SETUP_GPU.md](SETUP_GPU.md) — 18× A6000 cluster configuration

---

## License

MIT License — open training pipeline, open weights (post v1 release).
