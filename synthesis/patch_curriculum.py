"""
patch_curriculum.py - Smart curriculum ordering for SealPatch container security training data.

Orders patches from simple to complex:
    1. Single CVE fix (one package upgrade)
    2. Multi-CVE fix (multiple packages)
    3. Base image upgrade
    4. Full security overhaul (root user + unpinned + outdated packages)

Coverage targets:
    apt-based: 30%
    npm: 25%
    pip: 25%
    multi-stage: 20%

Usage:
    python synthesis/patch_curriculum.py --input data/ --output data/curriculum/
    python synthesis/patch_curriculum.py --stats
"""

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Optional

DATA_DIR = Path(__file__).parents[1] / "data"
CURRICULUM_DIR = DATA_DIR / "curriculum"

# ─── Coverage targets ─────────────────────────────────────────────────────────
COVERAGE_TARGETS = {
    "apt": 0.25,
    "npm": 0.25,
    "pip": 0.25,
    "maven": 0.05,
    "multi_stage": 0.20,
}

# ─── Complexity levels ────────────────────────────────────────────────────────
# 1 = Single CVE/package fix (surgical)
# 2 = Multiple packages, same ecosystem
# 3 = Base image upgrade
# 4 = Cross-ecosystem fix (apt + pip)
# 5 = Full security overhaul (base image + users + all packages)

COMPLEXITY_LABELS = {
    1: "single_cve_fix",
    2: "multi_cve_fix",
    3: "base_image_upgrade",
    4: "cross_ecosystem_fix",
    5: "full_security_overhaul",
}


def detect_ecosystem(record: dict) -> str:
    """Detect the primary package ecosystem from a record."""
    ecosystem = record.get("ecosystem", "").lower()
    if ecosystem in ("pip", "pypi"):
        return "pip"
    if ecosystem in ("npm", "yarn"):
        return "npm"
    if ecosystem in ("debian", "ubuntu", "apt"):
        return "apt"
    if ecosystem in ("alpine", "apk"):
        return "apt"  # group with apt for curriculum purposes
    if ecosystem == "maven":
        return "maven"  # Java/Maven — separate ecosystem from apt

    # Infer from Dockerfile content
    dockerfile = record.get("dockerfile", "")
    if "apt-get install" in dockerfile or "apt install" in dockerfile:
        return "apt"
    if "pip install" in dockerfile or "pip3 install" in dockerfile:
        return "pip"
    if "npm install" in dockerfile or "yarn install" in dockerfile:
        return "npm"
    if "AS " in dockerfile and "FROM " in dockerfile:
        return "multi_stage"

    # Infer from filename patterns
    files = [f.get("filename", "") for f in record.get("security_files_changed", [])]
    for f in files:
        if "requirements" in f or "setup.py" in f or "pyproject.toml" in f:
            return "pip"
        if "package.json" in f or "yarn.lock" in f:
            return "npm"

    return "apt"  # default


def compute_complexity(record: dict) -> int:
    """Compute patch complexity level (1-5)."""
    record.get("type", "")
    issues = record.get("analysis", {}).get("issues", [])
    issue_count = len(issues)
    affected_packages = record.get("affected_packages", [])

    # Multi-stage Dockerfiles are inherently more complex
    dockerfile = record.get("dockerfile", "")
    is_multi_stage = bool(
        dockerfile and "AS " in dockerfile and dockerfile.count("FROM") > 1
    )
    if is_multi_stage:
        return 5 if issue_count >= 3 else 4

    # Full security overhaul indicators
    if issue_count >= 4:
        return 5

    # Cross-ecosystem fix
    if issue_count >= 3:
        return 4

    # Base image upgrade
    has_base_image_issue = any(
        i.get("issue") in ("unpinned_base_image", "outdated_openssl") for i in issues
    )
    if has_base_image_issue and issue_count >= 2:
        return 3

    # Multi-CVE fix
    if len(affected_packages) > 1 or issue_count == 2:
        return 2

    # Single CVE fix (surgical)
    return 1


def score_patch_quality(record: dict) -> float:
    """Score the quality of a patch record as training data."""
    score = 0.3

    # Has a concrete fix
    if record.get("patch_instruction") or record.get("dockerfile_fix"):
        score += 0.2
    if record.get("first_patched_version") or record.get("fixed_version"):
        score += 0.15

    # Has diff
    if record.get("diff_preview") or record.get("patched_dockerfile"):
        score += 0.15

    # CVE severity
    severity = record.get("severity", "UNKNOWN").upper()
    if severity == "CRITICAL":
        score += 0.2
    elif severity == "HIGH":
        score += 0.15
    elif severity == "MEDIUM":
        score += 0.1

    # Well-known CVEs (log4shell, etc.)
    if record.get("is_high_value"):
        score += 0.15

    # Has CVSS score
    cvss = record.get("cvss_score", 0.0)
    if cvss >= 9.0:
        score += 0.1
    elif cvss >= 7.0:
        score += 0.05

    return min(1.0, score)


def load_jsonl(filepath: Path) -> list[dict]:
    records = []
    if not filepath.exists():
        return records
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def balance_by_ecosystem(
    records_by_eco: dict[str, list],
    total_target: Optional[int] = None,
) -> list[dict]:
    """Balance records according to ecosystem coverage targets."""
    if total_target is None:
        total_target = sum(len(v) for v in records_by_eco.values())

    balanced = []
    for eco, target_frac in COVERAGE_TARGETS.items():
        target_count = int(total_target * target_frac)
        available = records_by_eco.get(eco, [])
        available.sort(key=lambda r: r.get("_quality_score", 0), reverse=True)

        if len(available) >= target_count:
            selected = available[:target_count]
        else:
            selected = available[:]
            # Upsample if needed
            while len(selected) < target_count and available:
                selected.extend(available[: target_count - len(selected)])
            selected = selected[:target_count]

        balanced.extend(selected)

    return balanced


def build_curriculum(records: list[dict]) -> list[dict]:
    """Build the final curriculum-ordered patch dataset."""
    # Enrich with metadata
    for rec in records:
        rec["_ecosystem"] = detect_ecosystem(rec)
        rec["_complexity"] = compute_complexity(rec)
        rec["_quality_score"] = score_patch_quality(rec)

    # Group by ecosystem
    by_eco: dict[str, list] = defaultdict(list)
    for rec in records:
        eco = rec.get("_ecosystem", "apt")
        if eco not in COVERAGE_TARGETS:
            eco = "apt"
        by_eco[eco].append(rec)

    print("\nRaw distribution:")
    for eco, recs in sorted(by_eco.items()):
        print(f"  {eco:12}: {len(recs):>6}")

    # Balance
    balanced = balance_by_ecosystem(by_eco)

    # Sort by complexity (curriculum order)
    balanced.sort(key=lambda r: (r["_complexity"], -r["_quality_score"]))

    # Tag
    for i, rec in enumerate(balanced):
        rec["_curriculum_position"] = i
        rec["_curriculum_tier"] = f"complexity_{rec['_complexity']}"
        rec["_curriculum_label"] = COMPLEXITY_LABELS.get(rec["_complexity"], "unknown")

    return balanced


def print_stats(records: list[dict]) -> None:
    by_eco: dict[str, int] = defaultdict(int)
    by_complexity: dict[int, int] = defaultdict(int)
    quality_sum = 0.0

    for rec in records:
        by_eco[rec.get("_ecosystem", "unknown")] += 1
        by_complexity[rec.get("_complexity", 0)] += 1
        quality_sum += rec.get("_quality_score", 0)

    total = len(records)
    print("\n=== PATCH CURRICULUM STATISTICS ===")
    print(f"Total records: {total}")
    print(f"Average quality: {quality_sum / max(total, 1):.3f}")

    print("\nBy ecosystem (coverage vs target):")
    for eco, count in sorted(by_eco.items(), key=lambda x: -x[1]):
        actual = 100 * count / max(total, 1)
        target = 100 * COVERAGE_TARGETS.get(eco, 0)
        print(f"  {eco:12}: {count:>6} ({actual:.1f}% vs {target:.0f}% target)")

    print("\nBy complexity:")
    for level in sorted(by_complexity.keys()):
        count = by_complexity[level]
        label = COMPLEXITY_LABELS.get(level, "unknown")
        print(f"  Level {level} ({label:25}): {count:>6}")


def main():
    parser = argparse.ArgumentParser(
        description="Build patch curriculum for SealPatch training data"
    )
    parser.add_argument("--input", type=Path, default=DATA_DIR)
    parser.add_argument("--output", type=Path, default=CURRICULUM_DIR)
    parser.add_argument("--stats", action="store_true")
    parser.add_argument("--total", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)

    input_files = [
        args.input / "nvd_container_cves.jsonl",
        args.input / "osv_vulnerabilities.jsonl",
        args.input / "github_security_advisories.jsonl",
        args.input / "ghsa_patch_diffs.jsonl",
        args.input / "dockerhub_dockerfiles.jsonl",
        args.input / "cve_dockerfile_links.jsonl",
    ]

    all_records = []
    for f in input_files:
        if f.exists():
            recs = load_jsonl(f)
            print(f"Loaded {len(recs):>6} records from {f.name}")
            all_records.extend(recs)
        else:
            print(f"  [skip] {f.name}")

    if not all_records:
        print("\nNo data found. Run discovery scripts first.")
        return

    print(f"\nTotal records: {len(all_records)}")
    curriculum = build_curriculum(all_records)

    if args.total and len(curriculum) > args.total:
        curriculum = curriculum[: args.total]

    if args.stats:
        print_stats(curriculum)
        return

    print_stats(curriculum)

    args.output.mkdir(parents=True, exist_ok=True)

    full_path = args.output / "patch_curriculum.jsonl"
    with open(full_path, "w") as f:
        for rec in curriculum:
            f.write(json.dumps(rec) + "\n")
    print(f"\nFull curriculum: {full_path} ({len(curriculum)} records)")

    by_level: dict[int, list] = defaultdict(list)
    for rec in curriculum:
        by_level[rec.get("_complexity", 1)].append(rec)

    for level, recs in sorted(by_level.items()):
        label = COMPLEXITY_LABELS.get(level, f"level_{level}")
        level_path = args.output / f"patch_{label}.jsonl"
        with open(level_path, "w") as f:
            for rec in recs:
                f.write(json.dumps(rec) + "\n")
        print(f"  Level {level} ({label}): {level_path} ({len(recs)} records)")

    hq = [r for r in curriculum if r.get("_quality_score", 0) >= 0.7]
    hq_path = args.output / "patch_high_quality.jsonl"
    with open(hq_path, "w") as f:
        for rec in hq:
            f.write(json.dumps(rec) + "\n")
    print(f"  High quality: {hq_path} ({len(hq)} records)")


if __name__ == "__main__":
    main()
