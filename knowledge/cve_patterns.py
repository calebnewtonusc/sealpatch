"""
SealPatch — CVE Pattern Knowledge Base
Curated patterns for common vulnerability classes across ecosystems.
Used to supplement model inference with deterministic heuristics
and provide fast-path fixes for well-known CVEs.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CVEPattern:
    """A known CVE pattern with deterministic remediation."""

    cve_id: str
    description: str
    ecosystem: str  # python, javascript, java, go, rust, container
    package_name: str
    vulnerable_range: str  # e.g. "<2.31.0", ">=1.0,<1.8"
    fixed_version: str
    base_image_fix: Optional[str] = None  # If base image bump is the fix
    category: str = "APP_DEP"
    cvss_score: float = 0.0
    notes: str = ""


@dataclass
class BaseImagePattern:
    """Known vulnerable base images and their safe replacements."""

    from_image: str  # e.g. "ubuntu:20.04"
    to_image: str  # e.g. "ubuntu:22.04"
    cves_fixed: list = field(default_factory=list)
    ecosystem: str = "container"
    notes: str = ""


# ── High-frequency Python CVEs ──────────────────────────────────────────────────

PYTHON_CVE_PATTERNS: list[CVEPattern] = [
    CVEPattern(
        cve_id="CVE-2023-32681",
        description="requests: SSRF via Proxy-Authorization header leak on redirect",
        ecosystem="python",
        package_name="requests",
        vulnerable_range="<2.31.0",
        fixed_version="2.31.0",
        category="APP_DEP",
        cvss_score=6.1,
        notes="Pin to requests>=2.31.0 or use 'requests>=2.31.0,<3'",
    ),
    CVEPattern(
        cve_id="CVE-2024-35195",
        description="requests: certificate verification bypass with improper redirect",
        ecosystem="python",
        package_name="requests",
        vulnerable_range="<2.32.0",
        fixed_version="2.32.0",
        category="APP_DEP",
        cvss_score=5.6,
    ),
    CVEPattern(
        cve_id="CVE-2022-40897",
        description="setuptools: ReDoS via package name",
        ecosystem="python",
        package_name="setuptools",
        vulnerable_range="<65.5.1",
        fixed_version="65.5.1",
        category="BUILD_TOOL",
        cvss_score=5.9,
        notes="Often appears as indirect dep — pip install --upgrade setuptools",
    ),
    CVEPattern(
        cve_id="CVE-2024-3651",
        description="idna: resource consumption via crafted argument",
        ecosystem="python",
        package_name="idna",
        vulnerable_range="<3.7",
        fixed_version="3.7",
        category="APP_DEP",
        cvss_score=6.5,
    ),
    CVEPattern(
        cve_id="CVE-2023-43804",
        description="urllib3: Cookie header not stripped on cross-origin redirect",
        ecosystem="python",
        package_name="urllib3",
        vulnerable_range="<1.26.17",
        fixed_version="1.26.17",
        category="APP_DEP",
        cvss_score=8.8,
    ),
    CVEPattern(
        cve_id="CVE-2023-45803",
        description="urllib3: Cookie header leak on POST redirect",
        ecosystem="python",
        package_name="urllib3",
        vulnerable_range="<1.26.18",
        fixed_version="1.26.18",
        category="APP_DEP",
        cvss_score=4.2,
    ),
    CVEPattern(
        cve_id="CVE-2022-42919",
        description="Python: Local privilege escalation via multiprocessing forkserver",
        ecosystem="python",
        package_name="python",
        vulnerable_range="<3.9.16,<3.10.9,<3.11.1",
        fixed_version="3.11.1",
        category="RUNTIME",
        cvss_score=7.8,
        base_image_fix="FROM python:3.11-slim",
    ),
    CVEPattern(
        cve_id="CVE-2023-27043",
        description="Python: email.parseaddr incorrect parsing of bare names in email addresses",
        ecosystem="python",
        package_name="python",
        vulnerable_range="<3.12.0b1",
        fixed_version="3.12.0",
        category="RUNTIME",
        cvss_score=5.3,
        base_image_fix="FROM python:3.12-slim",
    ),
    CVEPattern(
        cve_id="CVE-2024-6345",
        description="setuptools: code execution via package URL in setup.py",
        ecosystem="python",
        package_name="setuptools",
        vulnerable_range="<70.0.0",
        fixed_version="70.0.0",
        category="BUILD_TOOL",
        cvss_score=8.8,
    ),
    CVEPattern(
        cve_id="CVE-2022-21699",
        description="ipython: arbitrary code execution via untrusted history file",
        ecosystem="python",
        package_name="ipython",
        vulnerable_range="<7.31.1",
        fixed_version="7.31.1",
        category="APP_DEP",
        cvss_score=8.8,
        notes="Dev-only — suppress if only in dev/test requirements",
    ),
]


# ── High-frequency JavaScript/Node.js CVEs ─────────────────────────────────────

JS_CVE_PATTERNS: list[CVEPattern] = [
    CVEPattern(
        cve_id="CVE-2023-30581",
        description="Node.js: permission model bypass via path traversal",
        ecosystem="javascript",
        package_name="node",
        vulnerable_range="18.0.0-18.19.0",
        fixed_version="18.20.0",
        category="RUNTIME",
        cvss_score=7.5,
        base_image_fix="FROM node:18.20-alpine",
    ),
    CVEPattern(
        cve_id="CVE-2024-21538",
        description="cross-spawn: ReDoS in argument handling",
        ecosystem="javascript",
        package_name="cross-spawn",
        vulnerable_range="<6.0.6",
        fixed_version="6.0.6",
        category="APP_DEP",
        cvss_score=7.5,
    ),
    CVEPattern(
        cve_id="CVE-2024-45296",
        description="path-to-regexp: ReDoS via backtracking",
        ecosystem="javascript",
        package_name="path-to-regexp",
        vulnerable_range="<0.1.10",
        fixed_version="0.1.10",
        category="APP_DEP",
        cvss_score=7.5,
    ),
    CVEPattern(
        cve_id="CVE-2024-4067",
        description="micromatch: ReDoS via crafted glob string",
        ecosystem="javascript",
        package_name="micromatch",
        vulnerable_range="<4.0.8",
        fixed_version="4.0.8",
        category="APP_DEP",
        cvss_score=7.5,
    ),
    CVEPattern(
        cve_id="CVE-2022-37599",
        description="loader-utils: prototype pollution",
        ecosystem="javascript",
        package_name="loader-utils",
        vulnerable_range="<1.4.2,>=2.0.0,<2.0.4",
        fixed_version="2.0.4",
        category="BUILD_TOOL",
        cvss_score=9.8,
    ),
]


# ── High-frequency Go CVEs ──────────────────────────────────────────────────────

GO_CVE_PATTERNS: list[CVEPattern] = [
    CVEPattern(
        cve_id="CVE-2023-44487",
        description="HTTP/2 rapid reset attack (CONTINUATION frame flood)",
        ecosystem="go",
        package_name="golang.org/x/net",
        vulnerable_range="<0.17.0",
        fixed_version="0.17.0",
        category="APP_DEP",
        cvss_score=7.5,
        notes="Also affects net/http — upgrade Go stdlib and golang.org/x/net",
    ),
    CVEPattern(
        cve_id="CVE-2023-39325",
        description="net/http: rapid stream resets cause excessive work",
        ecosystem="go",
        package_name="golang.org/x/net",
        vulnerable_range="<0.17.0",
        fixed_version="0.17.0",
        category="RUNTIME",
        cvss_score=7.5,
    ),
]


# ── Base image vulnerability mapping ───────────────────────────────────────────

BASE_IMAGE_PATTERNS: list[BaseImagePattern] = [
    BaseImagePattern(
        from_image="ubuntu:20.04",
        to_image="ubuntu:22.04",
        cves_fixed=["CVE-2022-0778", "CVE-2022-25315", "CVE-2023-0464"],
        notes="Ubuntu 20.04 has openssl 1.1 with multiple HIGH CVEs; 22.04 ships 3.0",
    ),
    BaseImagePattern(
        from_image="ubuntu:18.04",
        to_image="ubuntu:22.04",
        cves_fixed=["CVE-2022-0778", "CVE-2021-3449", "CVE-2021-3450"],
        notes="Ubuntu 18.04 EOL — migrate to 22.04",
    ),
    BaseImagePattern(
        from_image="python:3.9",
        to_image="python:3.12-slim",
        cves_fixed=["CVE-2022-42919", "CVE-2023-27043"],
        notes="Python 3.9 approaching EOL; 3.12-slim has fewer packages = smaller attack surface",
    ),
    BaseImagePattern(
        from_image="python:3.10",
        to_image="python:3.12-slim",
        cves_fixed=["CVE-2023-27043"],
        notes="3.10 EOL Oct 2026; prefer slim variant",
    ),
    BaseImagePattern(
        from_image="node:16",
        to_image="node:20-alpine",
        cves_fixed=["CVE-2023-30581", "CVE-2023-32002"],
        notes="Node 16 EOL. Migrate to LTS (20). Alpine reduces attack surface.",
    ),
    BaseImagePattern(
        from_image="node:18.12-alpine",
        to_image="node:18.20-alpine",
        cves_fixed=["CVE-2023-30581"],
        notes="18.12 has permission model bypass; 18.20 is patched LTS",
    ),
    BaseImagePattern(
        from_image="debian:buster",
        to_image="debian:bookworm-slim",
        cves_fixed=["CVE-2022-3786", "CVE-2022-3602"],
        notes="buster/oldoldstable EOL; bookworm (12) is current stable",
    ),
    BaseImagePattern(
        from_image="debian:bullseye",
        to_image="debian:bookworm-slim",
        cves_fixed=["CVE-2023-0464", "CVE-2023-0465"],
        notes="bullseye receives security updates but bookworm has newer packages",
    ),
    BaseImagePattern(
        from_image="alpine:3.14",
        to_image="alpine:3.19",
        cves_fixed=["CVE-2022-0778", "CVE-2022-2068"],
        notes="Alpine 3.14 EOL; 3.19 is current",
    ),
    BaseImagePattern(
        from_image="alpine:3.15",
        to_image="alpine:3.19",
        cves_fixed=["CVE-2022-0778"],
        notes="Alpine 3.15 EOL; migrate to 3.19",
    ),
]


# ── Lookup helpers ──────────────────────────────────────────────────────────────

_CVE_LOOKUP: dict = {}
_IMAGE_LOOKUP: dict = {}


def _build_lookup():
    global _CVE_LOOKUP, _IMAGE_LOOKUP
    all_patterns = PYTHON_CVE_PATTERNS + JS_CVE_PATTERNS + GO_CVE_PATTERNS
    for p in all_patterns:
        _CVE_LOOKUP[p.cve_id] = p
    for b in BASE_IMAGE_PATTERNS:
        _IMAGE_LOOKUP[b.from_image] = b


_build_lookup()


def lookup_cve(cve_id: str) -> Optional[CVEPattern]:
    """Look up a known CVE pattern by ID."""
    return _CVE_LOOKUP.get(cve_id)


def lookup_base_image(from_image: str) -> Optional[BaseImagePattern]:
    """Look up a known vulnerable base image and its safe replacement."""
    # Exact match first
    if from_image in _IMAGE_LOOKUP:
        return _IMAGE_LOOKUP[from_image]
    # Prefix match (e.g. "python:3.9-slim" → "python:3.9" or "python:3.9.16" → "python:3.9")
    for key, val in _IMAGE_LOOKUP.items():
        if from_image.startswith(key.split(":")[0] + ":"):
            base_version = from_image.split(":")[1].split("-")[0]
            key_version = key.split(":")[1].split("-")[0]
            # Exact match
            if base_version == key_version:
                return val
            # Patch version match: "3.9.16" starts with "3.9."
            if base_version.startswith(key_version + "."):
                return val
    return None


def find_patterns_for_cves(cve_ids: list) -> list:
    """Return all known patterns matching the given CVE ID list."""
    results = []
    for cve_id in cve_ids:
        pattern = lookup_cve(cve_id)
        if pattern:
            results.append(pattern)
    return results


def is_dev_only_package(package_name: str, ecosystem: str) -> bool:
    """Heuristic: is this package typically dev-only?"""
    DEV_PACKAGES = {
        "python": {
            "pytest",
            "coverage",
            "mypy",
            "black",
            "flake8",
            "pylint",
            "sphinx",
            "ipython",
            "notebook",
            "jupyterlab",
            "bandit",
            "tox",
            "hypothesis",
            "factory-boy",
            "faker",
            "responses",
        },
        "javascript": {
            "jest",
            "mocha",
            "chai",
            "eslint",
            "prettier",
            "nodemon",
            "webpack",
            "babel",
            "typescript",
            "ts-node",
            "vitest",
            "playwright",
            "cypress",
        },
    }
    dev_set = DEV_PACKAGES.get(ecosystem, set())
    return package_name.lower() in dev_set


def extract_from_image(dockerfile: str) -> Optional[str]:
    """Extract the FROM image from a Dockerfile."""
    for line in dockerfile.splitlines():
        line = line.strip()
        if line.upper().startswith("FROM ") and "AS" not in line.upper():
            return line.split()[1]
    return None
