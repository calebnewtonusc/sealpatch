"""
SealPatch — CVE Taxonomy
Defines the 5-category CVE taxonomy and associated prioritization logic.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class CVECategory(str, Enum):
    """Primary CVE actionability category."""

    BASE_IMAGE = "BASE_IMAGE_CVE"
    APP_DEP = "APP_DEP_CVE"
    RUNTIME = "RUNTIME_CVE"
    BUILD_TOOL = "BUILD_TOOL_CVE"
    SCANNER_ARTIFACT = "SCANNER_ARTIFACT"
    UNKNOWN = "UNKNOWN"


class CVESubCategory(str, Enum):
    """Sub-categories for APP_DEP CVEs."""

    DIRECT = "direct_dep"
    TRANSITIVE = "transitive_dep"
    DEV_ONLY = "dev_only"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NEGLIGIBLE = "NEGLIGIBLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class CVEFinding:
    """A single CVE finding from a scanner."""

    cve_id: str
    severity: Severity
    cvss_score: float
    package_name: str
    installed_version: str
    fixed_version: Optional[str]
    artifact_type: str  # image, file, dir
    artifact_location: str  # layer path in Docker image
    description: str = ""


@dataclass
class CategorizedCVE:
    """A CVE finding with SealPatch categorization."""

    finding: CVEFinding
    category: CVECategory
    subcategory: CVESubCategory = CVESubCategory.UNKNOWN
    should_fix: bool = True
    suppression_rationale: str = ""
    fix_strategy: str = ""
    estimated_risk: float = 0.0  # 0-1, accounts for exploitability context


def categorize_cve(finding: CVEFinding, dockerfile_context: str = "") -> CategorizedCVE:
    """
    Categorize a CVE finding based on its artifact location and package type.
    This is the heuristic pre-categorization; the SealPatch model provides deep analysis.
    """
    loc = finding.artifact_location.lower()
    pkg = finding.package_name.lower()

    # Scanner artifact CVEs (Grype/Trivy dependencies) — never actionable
    scanner_pkgs = {"grype", "syft", "trivy", "anchore"}
    if any(sp in pkg for sp in scanner_pkgs):
        return CategorizedCVE(
            finding=finding,
            category=CVECategory.SCANNER_ARTIFACT,
            should_fix=False,
            suppression_rationale="CVE is in the security scanner itself, not in your application",
        )

    # Build tool CVEs
    build_tools = {"cargo", "pip", "npm", "maven", "gradle", "bundler", "go"}
    build_paths = ["/usr/local/bin/pip", "/.cargo/", "/usr/local/cargo"]
    if pkg in build_tools or any(bp in loc for bp in build_paths):
        return CategorizedCVE(
            finding=finding,
            category=CVECategory.BUILD_TOOL,
            should_fix=finding.severity in (Severity.CRITICAL, Severity.HIGH),
            fix_strategy="Upgrade build tool in Dockerfile RUN step, or use newer base image",
        )

    # Runtime CVEs (Python, Node, Java runtimes)
    runtime_pkgs = {"python", "node", "nodejs", "openjdk", "java", "ruby", "go"}
    if any(rt in pkg for rt in runtime_pkgs) and "lib" not in pkg:
        return CategorizedCVE(
            finding=finding,
            category=CVECategory.RUNTIME,
            fix_strategy="Pin runtime version via FROM image tag or apt-get install with specific version",
        )

    # Base image layer CVEs (OS packages from the base image)
    os_pkg_indicators = ["/usr/lib/", "/lib/x86_64", "/usr/share/", "layer.tar"]
    if any(ind in loc for ind in os_pkg_indicators):
        return CategorizedCVE(
            finding=finding,
            category=CVECategory.BASE_IMAGE,
            fix_strategy="Upgrade base image to patched tag, or add RUN apt-get upgrade to Dockerfile",
        )

    # Application dependency CVEs — check for dev-only
    dev_indicators_in_path = [
        "dev-requirements",
        "requirements-dev",
        "test-requirements",
        "requirements/test",
        "requirements/dev",
        "dev_requirements",
        "/node_modules/.bin/",
        "devDependencies",
    ]
    is_dev_only = any(
        di in loc or di in dockerfile_context.lower() for di in dev_indicators_in_path
    )

    if is_dev_only:
        return CategorizedCVE(
            finding=finding,
            category=CVECategory.APP_DEP,
            subcategory=CVESubCategory.DEV_ONLY,
            should_fix=False,
            suppression_rationale=(
                f"{finding.package_name} is a development-only dependency "
                f"and does not ship to production. This CVE does not affect your production image."
            ),
        )

    return CategorizedCVE(
        finding=finding,
        category=CVECategory.APP_DEP,
        subcategory=CVESubCategory.DIRECT,
        fix_strategy=f"Upgrade {finding.package_name} to {finding.fixed_version or 'latest patched version'}",
    )


def prioritize_findings(findings: list[CategorizedCVE]) -> list[CategorizedCVE]:
    """
    Sort findings by priority: should_fix=True first, then by CVSS score descending.
    Suppressible findings (dev-only, scanner artifact) are moved to the end.
    """
    actionable = [f for f in findings if f.should_fix]
    suppressible = [f for f in findings if not f.should_fix]

    severity_order = {
        Severity.CRITICAL: 5,
        Severity.HIGH: 4,
        Severity.MEDIUM: 3,
        Severity.LOW: 2,
        Severity.NEGLIGIBLE: 1,
        Severity.UNKNOWN: 0,
    }

    actionable.sort(
        key=lambda c: (
            severity_order.get(c.finding.severity, 0),
            c.finding.cvss_score,
        ),
        reverse=True,
    )

    return actionable + suppressible


def group_by_root_cause(
    findings: list[CategorizedCVE],
) -> dict[str, list[CategorizedCVE]]:
    """
    Group CVE findings by root cause to minimize PR count.
    Each group will become a single PR.
    """
    groups: dict[str, list[CategorizedCVE]] = {}

    for cve in findings:
        if not cve.should_fix:
            continue

        if cve.category == CVECategory.BASE_IMAGE:
            # All base image CVEs go in one PR
            key = "base_image_upgrade"
        elif cve.category == CVECategory.APP_DEP:
            # Group by package name (one PR per direct dep upgrade)
            key = f"dep_{cve.finding.package_name}"
        elif cve.category == CVECategory.RUNTIME:
            key = "runtime_upgrade"
        elif cve.category == CVECategory.BUILD_TOOL:
            key = "build_tool_upgrade"
        else:
            key = "misc"

        if key not in groups:
            groups[key] = []
        groups[key].append(cve)

    return groups


def parse_grype_sarif(sarif_json: dict) -> list[CVEFinding]:
    """Parse a Grype SARIF scan result into CVEFinding objects."""
    findings = []
    runs = sarif_json.get("runs", [])
    for run in runs:
        results = run.get("results", [])
        for result in results:
            rule_id = result.get("ruleId", "")  # CVE-XXXX-YYYY
            message = result.get("message", {}).get("text", "")
            locations = result.get("locations", [])

            for loc in locations:
                phys_loc = loc.get("physicalLocation", {})
                artifact = phys_loc.get("artifactLocation", {}).get("uri", "")
                phys_loc.get("region", {})

                # Extract severity from SARIF properties
                level = result.get("level", "warning")
                severity_map = {
                    "error": Severity.CRITICAL,
                    "warning": Severity.HIGH,
                    "note": Severity.MEDIUM,
                    "none": Severity.LOW,
                }
                severity = severity_map.get(level, Severity.UNKNOWN)

                # Extract package info from properties
                props = result.get("properties", {})
                findings.append(
                    CVEFinding(
                        cve_id=rule_id,
                        severity=severity,
                        cvss_score=props.get("cvss_score", 0.0),
                        package_name=props.get("package_name", "unknown"),
                        installed_version=props.get("installed_version", "unknown"),
                        fixed_version=props.get("fixed_version"),
                        artifact_type=props.get("artifact_type", "unknown"),
                        artifact_location=artifact,
                        description=message[:500],
                    )
                )

    return findings
