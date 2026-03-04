# SealPatch — Model Card

## Model Overview

| Property | Value |
|----------|-------|
| **Model name** | SealPatch v1 |
| **Base model** | Qwen/Qwen2.5-7B-Coder-Instruct |
| **Total parameters** | 7.6B |
| **Trainable parameters (LoRA)** | ~168M (2.2%) |
| **LoRA rank** | 64 / alpha 128 |
| **Context length** | 16,384 tokens |
| **Training stages** | SFT → GRPO (CVE-RL) → DPO |
| **Training hardware** | 18× NVIDIA A6000 48GB |
| **Training duration** | ~13 hours total |
| **License** | Apache 2.0 |
| **HuggingFace** | `calebnewtonusc/sealpatch-v1` (post-release) |

---

## Intended Use

SealPatch is designed to:

1. **Categorize** CVE findings from Grype/Trivy scan reports into 5 actionable categories
2. **Generate** minimal fix diffs (Dockerfile changes, lockfile updates) that eliminate CVEs
3. **Suppress** dev-only CVEs with documented rationale (these don't affect production)
4. **Validate** that proposed fixes preserve application behavior (CI must stay green)

**Intended users**: DevSecOps engineers, platform security teams, CI/CD pipeline integrators

**Intended integration**: GitHub Actions security workflows, Grype/Trivy scan post-processors, automated PR generation pipelines

---

## Capabilities

### What SealPatch Does Well

- **Base image CVE remediation**: Pinning base images to patched tags with minimal risk
- **Direct dep CVEs (Python, npm, Go)**: Finding the minimal version bump that patches the CVE
- **Dev-only CVE suppression**: Accurately identifying which CVEs affect only dev dependencies
- **Batch grouping**: Organizing multiple CVEs into ≤5 PRs by root cause (not 1 PR per CVE)
- **CVSS-weighted prioritization**: Focusing on CRITICAL/HIGH, documenting MEDIUM/LOW

### What SealPatch Does Not Do

- **Exploit analysis**: SealPatch does not determine if a CVE is actually exploitable in your specific usage pattern. It eliminates by version, not by reachability.
- **Custom/internal package CVEs**: SealPatch is trained on public package CVEs only. Internal package vulnerabilities require custom tooling.
- **Infrastructure CVEs**: AWS, GCP, Azure service-level CVEs are not in scope (v1). Infrastructure scanning requires cloud-native tools.
- **Binary CVEs**: SealPatch analyzes source artifacts (Dockerfiles, lockfiles). CVEs in compiled binaries require binary analysis tools (e.g., Syft + SBOM).
- **SBOM generation**: SealPatch fixes CVEs; it does not generate SBOMs.

---

## Training Data

- ~400,000 (scan_results, artifact, fix_diff, ci_outcome) tuples
- Sources: CVE remediation commits, OSV/NVD/GHSA corpus, Snyk/Dependabot PRs, container image history, synthesized pairs
- Ecosystems: Python (25%), npm/Node (25%), Go (20%), Java/Maven (15%), Ruby/Cargo (15%)
- CVE categories: BASE_IMAGE (20%), APP_DEP (50%), RUNTIME (15%), BUILD_TOOL (10%), SCANNER_ARTIFACT (5%)

---

## SealBench Results (Target)

| Scenario Type | CVE Elimination | Behavior Preserved |
|---------------|-----------------|--------------------|
| Base image CVEs | >90% | >98% |
| Direct dep CVEs | >85% | >95% |
| Transitive dep CVEs | >75% | >92% |
| Dev-only suppression | >85% correct | N/A |
| Mixed (real repo) | >80% overall | >95% |

---

## Limitations and Biases

- **Transitive dep complexity**: Deep transitive dependency conflicts (5+ levels) may require manual intervention that SealPatch cannot fully automate.
- **Java ecosystem**: Maven/Gradle dependency resolution is complex; Java CVE fix rate is lower than Python/npm.
- **Multi-stage Docker builds**: SealPatch handles multi-stage builds but may miss CVEs introduced in intermediate stages if the final stage appears clean.
- **Version range conservatism**: SealPatch prefers pinning to specific fixed versions over ranges (`==2.31.0` vs `>=2.31.0`). This is safer but may cause future drift.
- **No exploit reachability analysis**: SealPatch eliminates CVEs by version. A CVE that exists in code you don't call may be eliminated unnecessarily (safe, but could generate noise).

---

## Ethical Considerations

- SealPatch generates code changes that affect production security posture. All PRs should be reviewed by a human security engineer before merge.
- Do not configure SealPatch to auto-merge PRs without review in v1.
- SealPatch is trained on public data only and should not be used to process scan results from internal proprietary code without review of the data handling implications.

---

## Citation

```bibtex
@inproceedings{newton2027sealpatch,
  title     = {SealPatch: Training a CVE Remediation Specialist with Behavior-Preserving Reinforcement Learning},
  author    = {Newton, Caleb and others},
  booktitle = {IEEE Symposium on Security and Privacy (S\&P)},
  year      = {2027}
}
```
