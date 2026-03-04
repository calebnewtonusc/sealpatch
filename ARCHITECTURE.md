# SealPatch Architecture

## Core Insight

CVE remediation is fundamentally a constrained optimization problem: minimize the CVE count subject to the constraint that application behavior is unchanged and CI stays green. Existing tools optimize for one or the other — they either find all CVEs (scanners) or bump deps without understanding behavior (Dependabot). SealPatch is trained to solve the full problem.

The training signal is uniquely clean: before scan count vs. after scan count, with CI pass/fail as the behavior preservation constraint. This gives SealPatch the same "free verifiable reward" property that DeepSeek-R1 uses for math reasoning — applied to security remediation.

---

## CVE Taxonomy (The Core Innovation)

SealPatch classifies every CVE finding into one of 5 actionable categories before generating any fix:

### Category 1: BASE_IMAGE_CVE
CVE exists in the Docker base image layer. Not in your code, not in your dependencies — in the OS.

**Fix strategy**: Upgrade base image tag (e.g., `ubuntu:22.04` → `ubuntu:22.04-20240301`) or switch to a distroless equivalent.
**Risk**: Low — base image upgrades rarely change app behavior, but OS package changes can affect path-dependent scripts.

### Category 2: APP_DEP_CVE
CVE exists in an application dependency (direct or transitive).

**Sub-types**:
- **2a: Direct dep** — CVE in a package you explicitly installed
- **2b: Transitive dep** — CVE in a dep-of-dep; may require indirect constraint
- **2c: Dev-only dep** — CVE in a dev dependency (linters, test frameworks); does NOT affect production

**Fix strategy**: For 2a and 2b: upgrade the dep. For 2c: document and suppress (dev deps don't ship to production).

### Category 3: RUNTIME_CVE
CVE in a runtime binary (python, node, java) installed in the container.

**Fix strategy**: Pin the runtime version in the Dockerfile's `apt-get install` or use a specific `-slim` image tag.

### Category 4: BUILD_TOOL_CVE
CVE in build tooling (cargo, pip, npm, gradle) used only during build.

**Fix strategy**: Upgrade build tools in the build stage. Does not affect the final container.

### Category 5: DEPENDENCY_OF_SCANNER
CVE is in a dependency of the security scanner itself (false positive from Grype/Trivy scanning their own output). Must be suppressed.

---

## The Critical Insight: Dev-Only CVE Suppression

A major source of "alert fatigue" in security tooling is CVEs in development dependencies. When your Python project's `dev-requirements.txt` has a CVE in pytest, that CVE does not affect your production Docker image — pytest is never installed in the production stage.

SealPatch is the first tool specifically trained to distinguish:
- **Production CVEs**: Must be fixed. Affect what ships to users.
- **Dev-only CVEs**: Suppress with rationale. Never affect production.

This distinction eliminates ~30-40% of typical alert volume as actionable suppressions rather than fixes.

---

## Training Pipeline

### Data Streams → Pairs

```
Stream 1: CVE Remediation Commits (35% — ~140k pairs)
  GitHub commit search: "fix CVE" OR "security patch" OR "bump.*CVE"
  → (Dockerfile_before, scan_results_before, Dockerfile_after, scan_results_after)
  Filter: scan_results_after has fewer CRITICAL/HIGH findings

Stream 2: OSV/NVD/GitHub Advisory Corpus (25% — ~100k pairs)
  CVE metadata → affected versions → fixed version → (vuln_context, fix_strategy)
  Synthesized: LLM converts CVE advisory to training pair

Stream 3: Snyk/Dependabot Security PRs (20% — ~80k pairs)
  PRs with label "security" that passed CI
  → (lockfile_before, scan_output, lockfile_after, ci_outcome)
  Filter: only include PRs where CI was green after merge

Stream 4: Container Image Update History (12% — ~48k pairs)
  Docker Hub public image scan history
  → (image:old_tag + scan, image:new_tag + scan) — delta shows CVE reduction

Stream 5: Synthesized Pairs (8% — ~32k pairs)
  LLM-generated Dockerfile + lockfile + scan → fix pairs
  Validated: run Grype on synthesized Dockerfile, confirm CVE count drops
```

### Stage 1: SFT

- **Base model**: Qwen2.5-7B-Coder-Instruct
- **Data**: ~400k (scan_results, artifact, fix_diff, cve_category) tuples
- **LoRA**: rank 64, alpha 128
- **Context**: 16,384 tokens (full scan report + Dockerfile + lockfile)
- **Duration**: ~7 hours on 18× A6000
- **Goal**: Model learns CVE taxonomy and per-category fix strategies

### Stage 2: CVE-Verified RL (GRPO)

**Reward signal**: CVE count reduction + CI green (behavior preserved)

```
reward = 0.0  (patch fails to apply)
reward = 0.0  (CI red after patch — behavior broken)
reward = 0.3  (CI green, but CVE count unchanged or increased)
reward = 0.5  (CI green, CVE count reduced but not to 0 CRITICAL/HIGH)
reward = 0.8  (CI green, all CRITICAL/HIGH CVEs eliminated)
reward = 1.0  (CI green, all CRITICAL/HIGH eliminated, PR count <= 3)
```

**Execution harness**:
1. Apply generated lockfile/Dockerfile changes
2. Run Grype scan on patched artifact
3. Run smoke tests in Docker sandbox
4. Compare CVE counts before/after

### Stage 3: DPO

**Preference pairs**: Minimal focused PR vs. "nuke everything and upgrade" PR

Chosen: upgrade only `libssl` from 1.1.1q to 1.1.1t (patches the specific CVE)
Rejected: upgrade from `ubuntu:20.04` to `ubuntu:24.04` (eliminates CVE but risks app behavior)

---

## Multi-Agent Orchestration

```
SealPatch Agent (Orchestrator)
├── Scan Agent
│   ├── run_grype(dockerfile_path)
│   ├── run_trivy(image_tag)
│   ├── parse_sarif(scan_output)
│   └── deduplicate_findings()
├── CVE Prioritizer
│   ├── categorize_cve()  ── SealPatch model call
│   ├── filter_dev_only()
│   ├── score_exploitability()
│   └── group_by_root_cause()
├── Patch Agent (per CVE group)
│   ├── BaseImagePatcher
│   │   ├── find_minimal_upgrade()
│   │   └── generate_dockerfile_diff()
│   ├── AppDepPatcher
│   │   ├── resolve_dep_graph()
│   │   ├── find_safe_version_range()
│   │   └── update_lockfile()
│   └── RuntimePatcher
│       └── pin_runtime_version()
├── Validation Agent
│   ├── apply_patch_sandbox()
│   ├── run_scan_post_patch()
│   ├── run_smoke_tests()
│   └── verify_cve_count_reduced()
└── PR Generator
    ├── group_patches_into_prs()  # Max 3-5 PRs per repo
    ├── write_cve_remediation_description()
    └── open_pr_via_github_api()
```

---

## SealBench

500 CVE remediation scenarios stratified by:
- CVE category (50 per category × 5 × 2 = 500 scenarios)
- Severity mix (all CRITICAL, mixed, mostly MEDIUM)
- Ecosystem (Python, Node, Go, Java, Alpine, Debian)
- Complexity (1 CVE, 10 CVEs, 100+ CVEs)

Metrics:
- **CVE elimination rate**: % of CRITICAL/HIGH CVEs eliminated
- **Behavior preservation rate**: % of scenarios where CI stays green
- **PR minimality**: Average number of PRs generated per repo
- **False positive suppression**: Dev-only CVE correctly suppressed %
- **Scan-to-PR latency**: Time from scan to PR open

---

## Model Specification

| Property | Value |
|----------|-------|
| Base model | Qwen2.5-7B-Coder-Instruct |
| Total parameters | 7.6B |
| Trainable (LoRA) | ~168M (2.2%) |
| Context length | 16,384 tokens |
| LoRA rank | 64 |
| Output format | `<category>` + `<fix>` + `<suppress>` + `<validate>` |
| Quantization (inference) | 4-bit GPTQ |
| Serving | vLLM |
| Latency (per repo scan→PR) | <30s |
