# Contributing to SealPatch

SealPatch improves with more CVE-fix pairs, better scan integration, and community-contributed ecosystem support.

---

## Contributing CVE-Fix Pairs

The highest-value contribution is verified (scan_before, fix_diff, scan_after_confirmed_clean) tuples.

### Format

```json
{
  "source": "community",
  "repo": "owner/repo",
  "language": "python",
  "dockerfile_before": "(Dockerfile content before fix)",
  "dockerfile_after": "(Dockerfile content after fix)",
  "scan_before": {"critical": 1, "high": 2, "cves": ["CVE-XXXX-YYYY"]},
  "scan_after": {"critical": 0, "high": 0, "cves": []},
  "fix_diff": "(unified diff of the fix)",
  "cve_categories": ["APP_DEP_CVE"],
  "cves_fixed": ["CVE-XXXX-YYYY"],
  "ci_outcome": "green",
  "verified_scan": false
}
```

### Requirements
- `scan_before` must be from an actual Grype or Trivy run (include scan tool + version)
- `fix_diff` must be the exact change that eliminated the CVE
- `ci_outcome` must reflect whether the fix preserved CI green in the source repo
- Do not submit CVE pairs from private/internal codebases

---

## Contributing SealBench Scenarios

Add evaluation scenarios to `evaluation/sealbench.py`:

```python
SEALBENCH_CASES.append(SealBenchCase(
    id="community_alpine_libexpat_001",
    dockerfile="""FROM alpine:3.16\nRUN apk add libexpat""",
    expected_cves_eliminated=["CVE-2022-40674"],
    cve_category=CVECategory.BASE_IMAGE_CVE,
    language="python",
    notes="libexpat CVE in Alpine 3.16 fixed in 3.17"
))
```

---

## Contributing Ecosystem Support

SealPatch's weakest areas are Java/Maven, Rust/Cargo, and PHP/Composer. To add ecosystem support:

1. Add scanner integration in `agents/scan_agent.py` for the ecosystem
2. Add dep graph resolver in `core/cve_taxonomy.py`
3. Add 10+ example CVE-fix pairs for the ecosystem
4. Open a GitHub Issue with tag `[ecosystem-support]`

---

## Code Style

- Python 3.11+ with type hints
- `loguru` for logging
- `typer` for CLI
- `ruff` for linting
- Tests in `tests/` with `pytest`

```bash
pip install -e ".[dev]"
ruff check .
pytest tests/ -v
```
