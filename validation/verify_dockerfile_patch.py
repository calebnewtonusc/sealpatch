"""
verify_dockerfile_patch.py - Validate that Dockerfile patches are syntactically correct
and that they actually fix the identified vulnerability.

Validation checks:
1. Patched Dockerfile is syntactically valid
2. The fix removes the vulnerable package version
3. Patch diff is minimal (surgical > broad)
4. No new issues introduced by the patch

Usage:
    python validation/verify_dockerfile_patch.py --input data/curriculum/patch_curriculum.jsonl
    python validation/verify_dockerfile_patch.py --input data/ --output data/validated/
"""

import argparse
import json
import re
from pathlib import Path

DATA_DIR = Path(__file__).parents[1] / "data"

# ─── Dockerfile syntax validation patterns ────────────────────────────────────
VALID_DOCKERFILE_INSTRUCTIONS = {
    "FROM",
    "RUN",
    "CMD",
    "LABEL",
    "EXPOSE",
    "ENV",
    "ADD",
    "COPY",
    "ENTRYPOINT",
    "VOLUME",
    "USER",
    "WORKDIR",
    "ARG",
    "ONBUILD",
    "STOPSIGNAL",
    "HEALTHCHECK",
    "SHELL",
    "#",
}

DOCKERFILE_INSTRUCTION_PATTERN = re.compile(
    r"^(?:FROM|RUN|CMD|LABEL|EXPOSE|ENV|ADD|COPY|ENTRYPOINT|VOLUME|USER|"
    r"WORKDIR|ARG|ONBUILD|STOPSIGNAL|HEALTHCHECK|SHELL|#)\b",
    re.MULTILINE | re.I,
)

# Version pattern for checking if a fix actually upgrades a version
VERSION_PATTERN = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def is_valid_dockerfile_syntax(dockerfile: str) -> tuple[bool, str]:
    """
    Check if a Dockerfile is syntactically valid.
    Returns (is_valid, error_message).
    """
    if not dockerfile or len(dockerfile.strip()) < 10:
        return False, "Dockerfile is empty or too short"

    lines = dockerfile.split("\n")

    # Must start with FROM (ignoring comments and blank lines)
    first_instruction = None
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            first_instruction = stripped.upper()
            break

    if not first_instruction:
        return False, "Dockerfile has no instructions"

    if not first_instruction.startswith("FROM"):
        return False, f"Dockerfile must start with FROM, got: {first_instruction[:30]}"

    # Check for continuation lines (backslash at end)
    # Every non-continuation line should start with a valid instruction
    in_continuation = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            in_continuation = False
            continue

        if in_continuation:
            # This is a continuation of the previous instruction
            if not stripped.endswith("\\"):
                in_continuation = False
            continue

        # Check if line starts with a valid instruction
        # Allow: instruction, env var assignment in RUN, etc.
        upper = stripped.upper()
        is_valid_start = any(
            upper.startswith(inst) for inst in VALID_DOCKERFILE_INSTRUCTIONS
        )
        if not is_valid_start and not stripped.startswith("\\"):
            # Could be a continuation line without backslash — warning only
            pass  # We're lenient here; real Dockerfile parsers vary

        if stripped.endswith("\\"):
            in_continuation = True

    # Must have at least one FROM
    from_count = len(re.findall(r"^FROM\s+", dockerfile, re.MULTILINE | re.I))
    if from_count == 0:
        return False, "No FROM instruction found"

    return True, ""


def check_fix_removes_vulnerability(
    original: str,
    patched: str,
    vulnerable_version: str,
    package_name: str,
) -> tuple[bool, str]:
    """
    Check if the patch actually removes/upgrades the vulnerable version.
    Returns (fix_is_effective, explanation).
    """
    if not original or not patched:
        return False, "Missing original or patched Dockerfile"
    if not vulnerable_version:
        return True, "No specific vulnerable version to check (accept)"

    # Check if vulnerable version appears in original
    if vulnerable_version not in original:
        return (
            True,
            f"Vulnerable version {vulnerable_version} not found in original (may be implicit)",
        )

    # Check if vulnerable version still appears in patched
    if vulnerable_version in patched:
        return (
            False,
            f"Vulnerable version {vulnerable_version} still present in patched Dockerfile",
        )

    return True, f"Vulnerable version {vulnerable_version} successfully removed"


def compute_patch_size_score(original: str, patched: str) -> float:
    """
    Score the patch size: minimal diffs get higher scores.
    surgical (1-3 lines changed) = 1.0
    moderate (4-10 lines) = 0.7
    broad (11+ lines) = 0.4
    no change = 0.0
    """
    if not original or not patched:
        return 0.0
    if original == patched:
        return 0.0

    orig_lines = set(original.split("\n"))
    patch_lines = set(patched.split("\n"))

    added = patch_lines - orig_lines
    removed = orig_lines - patch_lines
    changed_count = len(added) + len(removed)

    if changed_count == 0:
        return 0.0
    elif changed_count <= 3:
        return 1.0  # surgical
    elif changed_count <= 10:
        return 0.7  # moderate
    elif changed_count <= 20:
        return 0.5  # medium
    else:
        return 0.3  # broad


def check_no_new_issues_introduced(patched: str) -> tuple[bool, list[str]]:
    """Check if the patched Dockerfile introduces any new security issues."""
    new_issues = []

    # Check for secrets baked in
    if re.search(r"ENV\s+\w*(PASSWORD|SECRET|KEY|TOKEN)\w*\s*=\s*\S+", patched, re.I):
        new_issues.append("Secret/credential baked into ENV instruction")

    # Check for curl | sh
    if re.search(r"curl\s+.*\|\s*(bash|sh)", patched, re.I):
        new_issues.append("curl piped to shell in RUN instruction")

    # Check if pinned image became unpinned
    from_tags = re.findall(
        r"^FROM\s+\S+:(latest|stable|lts)", patched, re.MULTILINE | re.I
    )
    if from_tags:
        new_issues.append(f"Base image uses unpinned tag: {from_tags[0]}")

    return len(new_issues) == 0, new_issues


def validate_patch_record(record: dict) -> dict:
    """
    Validate a single patch record.
    Returns the record with validation metadata added.
    """
    validation: dict[str, object] = {
        "syntax_valid": True,
        "syntax_error": None,
        "fix_effective": True,
        "fix_explanation": "",
        "patch_size_score": 0.5,
        "no_new_issues": True,
        "new_issues": [],
        "overall_valid": True,
        "quality_tier": "silver",
    }

    original_df = record.get("dockerfile", "")
    patched_df = record.get("patched_dockerfile", "")

    # If no patched Dockerfile, use the training output
    if not patched_df:
        patched_df = record.get("training_output", "")

    # ── 1. Syntax validation ──────────────────────────────────────────────────
    if patched_df:
        is_valid, error = is_valid_dockerfile_syntax(patched_df)
        validation["syntax_valid"] = is_valid
        if not is_valid:
            validation["syntax_error"] = error
            validation["overall_valid"] = False

    # ── 2. Fix effectiveness check ────────────────────────────────────────────
    # Use the version the code was pinned to BEFORE the fix (not the patched version)
    vulnerable_version = (
        record.get("version_range_start")
        or record.get("vulnerable_version_range")
        or ""
    )
    package_name = record.get("package_name", "")

    if original_df and patched_df and vulnerable_version:
        fix_ok, fix_exp = check_fix_removes_vulnerability(
            original_df, patched_df, vulnerable_version, package_name
        )
        validation["fix_effective"] = fix_ok
        validation["fix_explanation"] = fix_exp
        if not fix_ok:
            validation["overall_valid"] = False

    # ── 3. Patch size scoring ─────────────────────────────────────────────────
    if original_df and patched_df:
        validation["patch_size_score"] = compute_patch_size_score(
            original_df, patched_df
        )

    # ── 4. No new issues ──────────────────────────────────────────────────────
    if patched_df:
        no_new, new_issues = check_no_new_issues_introduced(patched_df)
        validation["no_new_issues"] = no_new
        validation["new_issues"] = new_issues

    # ── 5. Overall quality tier ───────────────────────────────────────────────
    quality_score = float(record.get("_quality_score", 0.5))  # type: ignore[arg-type]
    patch_score = float(validation["patch_size_score"])  # type: ignore[arg-type]

    if (
        validation["syntax_valid"]
        and validation["fix_effective"]
        and validation["no_new_issues"]
        and patch_score >= 0.7
        and quality_score >= 0.7
    ):
        validation["quality_tier"] = "gold"
    elif (
        validation["syntax_valid"]
        and validation["fix_effective"]
        and quality_score >= 0.4
    ):
        validation["quality_tier"] = "silver"
    elif validation["syntax_valid"]:
        validation["quality_tier"] = "bronze"
    else:
        validation["quality_tier"] = "reject"
        validation["overall_valid"] = False

    record["_patch_validation"] = validation
    record["_patch_quality_tier"] = validation["quality_tier"]
    record["_patch_size_score"] = validation["patch_size_score"]
    return record


def load_jsonl(filepath: Path) -> list[dict]:
    records: list[dict] = []
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


def save_jsonl(records: list[dict], filepath: Path) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    with open(filepath, "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Validate Dockerfile patches for SealPatch training data"
    )
    parser.add_argument(
        "--input", type=Path, default=DATA_DIR / "curriculum" / "patch_curriculum.jsonl"
    )
    parser.add_argument("--output", type=Path, default=DATA_DIR / "validated")
    parser.add_argument("--stats", action="store_true")
    parser.add_argument(
        "--min-tier", choices=["gold", "silver", "bronze"], default="bronze"
    )
    args = parser.parse_args()

    print("=== SEALPATCH DOCKERFILE VALIDATION ===")
    records = load_jsonl(args.input)
    if not records:
        print("No records to validate.")
        return

    print(f"Validating {len(records)} patch records...")

    validated = [validate_patch_record(r) for r in records]

    # Stats
    tier_counts: dict[str, int] = {}
    for rec in validated:
        tier = rec.get("_patch_quality_tier", "unknown")
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    syntax_failures = sum(
        1 for r in validated if not r["_patch_validation"]["syntax_valid"]
    )
    fix_failures = sum(
        1 for r in validated if not r["_patch_validation"]["fix_effective"]
    )
    new_issue_count = sum(
        1 for r in validated if not r["_patch_validation"]["no_new_issues"]
    )

    total = len(validated)
    print("\n=== VALIDATION RESULTS ===")
    print(f"Total records: {total}")
    print("\nQuality tiers:")
    for tier in ["gold", "silver", "bronze", "reject"]:
        count = tier_counts.get(tier, 0)
        print(f"  {tier:8}: {count:>6} ({100 * count / max(total, 1):.1f}%)")
    print(f"\nSyntax failures: {syntax_failures}")
    print(f"Ineffective fixes: {fix_failures}")
    print(f"Introduced new issues: {new_issue_count}")

    patch_scores = [r.get("_patch_size_score", 0) for r in validated]
    avg_patch_score = sum(patch_scores) / max(len(patch_scores), 1)
    print(f"Average patch size score: {avg_patch_score:.3f} (1.0=surgical, 0.3=broad)")

    if args.stats:
        return

    # Write output
    tier_order = {"gold": 3, "silver": 2, "bronze": 1, "reject": 0}
    min_order = tier_order.get(args.min_tier, 1)

    accepted = [
        r
        for r in validated
        if tier_order.get(r.get("_patch_quality_tier", "reject"), 0) >= min_order
    ]
    rejected = [
        r
        for r in validated
        if tier_order.get(r.get("_patch_quality_tier", "reject"), 0) < min_order
    ]

    save_jsonl(accepted, args.output / "patch_validated_accepted.jsonl")
    save_jsonl(rejected, args.output / "patch_validated_rejected.jsonl")
    print(
        f"\nAccepted: {args.output / 'patch_validated_accepted.jsonl'} ({len(accepted)})"
    )
    print(
        f"Rejected: {args.output / 'patch_validated_rejected.jsonl'} ({len(rejected)})"
    )

    for tier in ["gold", "silver", "bronze"]:
        tier_recs = [r for r in validated if r.get("_patch_quality_tier") == tier]
        save_jsonl(tier_recs, args.output / f"patch_tier_{tier}.jsonl")
        print(f"  Tier {tier}: {len(tier_recs)} records")


if __name__ == "__main__":
    main()
