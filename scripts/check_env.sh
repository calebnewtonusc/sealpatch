#!/usr/bin/env bash
# SealPatch — Environment Verification Script
# Checks all required dependencies, credentials, and hardware before training.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
WARN=0

ok() {
	echo -e "${GREEN}[PASS]${NC} $*"
	((PASS++))
}
fail() {
	echo -e "${RED}[FAIL]${NC} $*"
	((FAIL++))
}
warn() {
	echo -e "${YELLOW}[WARN]${NC} $*"
	((WARN++))
}

echo "=============================================="
echo "  SealPatch Environment Check"
echo "=============================================="
echo ""

# Python version
echo "--- Python ---"
if python3 --version 2>/dev/null | grep -q "3\.(10\|11\|12)"; then
	ok "Python $(python3 --version 2>&1)"
else
	fail "Python 3.10+ required (got: $(python3 --version 2>&1 || echo 'not found'))"
fi

# Required env vars
echo ""
echo "--- Environment Variables ---"
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
	ok "GITHUB_TOKEN is set"
else
	fail "GITHUB_TOKEN is not set — required for Dockerfile discovery"
fi

for var in NVD_API_KEY WANDB_API_KEY ANTHROPIC_API_KEY; do
	if [[ -n "${!var:-}" ]]; then
		ok "$var is set"
	else
		warn "$var not set (optional but recommended)"
	fi
done

# Grype
echo ""
echo "--- CVE Scanners ---"
GRYPE_BIN="${GRYPE_BIN:-grype}"
if "$GRYPE_BIN" version &>/dev/null; then
	ok "Grype: $($GRYPE_BIN version | head -1)"
else
	fail "Grype not found at '$GRYPE_BIN'. Install: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh"
fi

TRIVY_BIN="${TRIVY_BIN:-trivy}"
if "$TRIVY_BIN" --version &>/dev/null; then
	ok "Trivy: $($TRIVY_BIN --version | head -1)"
else
	warn "Trivy not found (optional for Dockerfile config scanning)"
fi

# Docker
echo ""
echo "--- Docker ---"
if docker info &>/dev/null; then
	ok "Docker daemon running ($(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'unknown'))"
else
	warn "Docker not available — container builds and smoke tests will be skipped"
fi

# GPU
echo ""
echo "--- GPU Hardware ---"
if command -v nvidia-smi &>/dev/null; then
	GPU_COUNT=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l)
	GPU_MEM=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -1 || echo 0)
	ok "$GPU_COUNT GPUs detected"
	if [[ $GPU_MEM -ge 48000 ]]; then
		ok "GPU memory: ${GPU_MEM}MiB (sufficient for A6000-class training)"
	elif [[ $GPU_MEM -ge 24000 ]]; then
		warn "GPU memory: ${GPU_MEM}MiB (may need to reduce batch size)"
	else
		fail "GPU memory: ${GPU_MEM}MiB (minimum 24GB required)"
	fi
	if [[ $GPU_COUNT -ge 8 ]]; then
		ok "$GPU_COUNT GPUs (full multi-GPU training available)"
	elif [[ $GPU_COUNT -ge 2 ]]; then
		warn "$GPU_COUNT GPUs (multi-GPU training available, slower than 18×)"
	else
		warn "1 GPU (single-GPU training only, ~10× slower)"
	fi
else
	fail "NVIDIA GPU / nvidia-smi not found — GPU training unavailable"
fi

# Python packages
echo ""
echo "--- Python Packages ---"
PACKAGES=("torch" "transformers" "peft" "trl" "deepspeed" "datasets" "loguru" "fastapi" "typer" "requests")
for pkg in "${PACKAGES[@]}"; do
	if python3 -c "import $pkg" 2>/dev/null; then
		VERSION=$(python3 -c "import $pkg; print(getattr($pkg, '__version__', 'installed'))" 2>/dev/null || echo "installed")
		ok "$pkg ($VERSION)"
	else
		fail "$pkg not installed — run: pip install -r requirements.txt"
	fi
done

# Optional packages
OPT_PACKAGES=("vllm" "datasketch" "aiohttp")
for pkg in "${OPT_PACKAGES[@]}"; do
	if python3 -c "import $pkg" 2>/dev/null; then
		ok "$pkg (optional — installed)"
	else
		warn "$pkg not installed (optional)"
	fi
done

# Disk space
echo ""
echo "--- Storage ---"
AVAIL_GB=$(df -BG . | awk 'NR==2 {gsub("G",""); print $4}' 2>/dev/null || echo 0)
if [[ $AVAIL_GB -ge 500 ]]; then
	ok "Disk: ${AVAIL_GB}GB available (sufficient for full pipeline)"
elif [[ $AVAIL_GB -ge 100 ]]; then
	warn "Disk: ${AVAIL_GB}GB available (may run short during training)"
else
	fail "Disk: ${AVAIL_GB}GB available (500GB+ recommended)"
fi

# Summary
echo ""
echo "=============================================="
echo "  Summary: ${PASS} passed, ${WARN} warnings, ${FAIL} failures"
echo "=============================================="
if [[ $FAIL -gt 0 ]]; then
	echo -e "${RED}Environment check FAILED. Fix issues above before training.${NC}"
	exit 1
elif [[ $WARN -gt 0 ]]; then
	echo -e "${YELLOW}Environment check passed with warnings.${NC}"
	exit 0
else
	echo -e "${GREEN}Environment check PASSED. Ready to train.${NC}"
	exit 0
fi
