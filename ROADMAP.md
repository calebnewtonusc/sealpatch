# SealPatch Roadmap

## v1 — SCAN + FIX (Q3 2026)

Core remediation agent. Scans Dockerfiles and lockfiles, categorizes CVEs, generates minimal fix PRs.

**Goals**:
- >80% CVE elimination rate on SealBench (500 scenarios)
- >95% behavior preservation (CI green after fix)
- <5 PRs per repo on average (minimal PR footprint)
- Dev-only CVE suppression accuracy >85%
- Open weights on HuggingFace

**Features**:
- 3-stage trained model (SFT → CVE-RL → DPO)
- 5-category CVE taxonomy (base image / app dep / runtime / build tool / scanner artifact)
- Grype + Trivy integration (parallel scan, merged SARIF)
- Docker sandbox behavior validation
- GitHub PR auto-generation with full CVE rationale
- SealBench evaluation suite (500 scenarios)
- REST API + GitHub Actions integration

**Paper Target**: IEEE S&P 2027 — "SealPatch: Training a CVE Remediation Specialist with Behavior-Preserving Reinforcement Learning"

---

## v1.5 — PREVENT (Q4 2026)

Shift-left security. Catch CVE risks before they merge.

**Goals**:
- Pre-merge CVE risk scoring with <5% false positive rate
- Block PRs that introduce CRITICAL CVEs before CI runs

**Features**:
- Pre-merge Dockerfile/lockfile analysis (GitHub PR check)
- "Will this PR introduce a CVE?" risk scoring before merge
- Developer-facing CVE explanation in PR review comments
- SBOM generation per repo (Software Bill of Materials)
- License compliance checking alongside CVE scanning
- Slack/PagerDuty integration for new CRITICAL CVEs in production

---

## v2 — CONTINUOUS (Q1 2027)

Always-current remediation. SealPatch monitors all repos and fixes CVEs as they emerge.

**Goals**:
- Zero CRITICAL CVEs lingering >24 hours in monitored repos
- Full org-wide CVE trend dashboard

**Features**:
- Org-wide CVE monitoring (all repos, all branches, all images)
- New CVE alert → auto-PR within 1 hour for CRITICAL findings
- CVE prioritization by business impact (which repos are customer-facing?)
- Remediation SLA tracking (CRITICAL: 24h, HIGH: 7d, MEDIUM: 30d)
- Continual fine-tuning from organization-specific remediation history
- Enterprise API with SSO, audit log, on-premise deployment

---

## v3 — GENERALIZE (2027)

Beyond containers. SealPatch for all software artifact types.

**Goals**:
- Full-stack security posture management
- Cloud infrastructure CVE remediation (Terraform, CloudFormation)
- Binary artifact analysis

**Features**:
- Cloud IaC remediation (Terraform, Pulumi, CDK)
- Lambda function CVE analysis and patching
- Kubernetes YAML security posture fixes
- Binary SBOM analysis for third-party artifacts
- Supply chain attack detection (typosquatting, dependency confusion)

---

## Research Paper Pipeline

| Paper | Target Venue | Core Contribution |
|-------|-------------|-------------------|
| SealPatch v1 | IEEE S&P 2027 | CVE taxonomy + behavior-preserving RL |
| Dev-Only Suppression | CCS 2027 | Automated dev/prod dependency distinction |
| SealBench | NDSS 2027 | First CVE remediation benchmark |
| Continuous Remediation | Oakland 2028 | Online RL for always-current security posture |
