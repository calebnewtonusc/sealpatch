#!/usr/bin/env bash
# SealPatch — Full Training Pipeline
# Runs all 5 stages: discovery → synthesis → training (SFT → RL → DPO)
# Usage: bash scripts/run_all.sh [--from-stage N] [--dry-run]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="$PROJECT_ROOT/logs"
FROM_STAGE=1
DRY_RUN=false

mkdir -p "$LOG_DIR"

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-stage) FROM_STAGE="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_DIR/run_all.log"; }
run() {
  local cmd="$*"
  log "Running: $cmd"
  if [[ "$DRY_RUN" == "true" ]]; then
    log "[DRY RUN] Would run: $cmd"
    return 0
  fi
  eval "$cmd" 2>&1 | tee -a "$LOG_DIR/run_all.log"
}

# Check environment
bash "$SCRIPT_DIR/check_env.sh" || { log "Environment check failed"; exit 1; }

log "==============================="
log "SealPatch Training Pipeline"
log "From stage: $FROM_STAGE"
log "==============================="

# Stage 1: CVE Data Discovery
if [[ $FROM_STAGE -le 1 ]]; then
  log "--- Stage 1: Dockerfile + CVE Discovery ---"
  run "python '$PROJECT_ROOT/discovery/dockerfile_crawler.py' \
    --output-dir '$PROJECT_ROOT/data/raw/artifacts' \
    --workers 12 \
    --max-repos 5000" 2>&1 | tee "$LOG_DIR/stage1_crawler.log"

  run "python '$PROJECT_ROOT/discovery/cve_database.py' \
    --sync-all \
    --output '$PROJECT_ROOT/data/raw/advisories'" 2>&1 | tee "$LOG_DIR/stage1_cve.log"
  log "Stage 1 complete."
fi

# Stage 2: Grype/Trivy Batch Scanning
if [[ $FROM_STAGE -le 2 ]]; then
  log "--- Stage 2: Batch CVE Scanning ---"
  run "python '$PROJECT_ROOT/agents/scan_agent.py' \
    --batch-mode \
    --artifacts-dir '$PROJECT_ROOT/data/raw/artifacts' \
    --output '$PROJECT_ROOT/data/scanned' \
    --workers 16" 2>&1 | tee "$LOG_DIR/stage2_scan.log"
  log "Stage 2 complete."
fi

# Stage 3: Synthesis (requires vLLM servers)
if [[ $FROM_STAGE -le 3 ]]; then
  log "--- Stage 3: Synthesis ---"
  log "Starting vLLM synthesis servers..."
  bash "$SCRIPT_DIR/start_vllm.sh" &
  VLLM_PID=$!
  sleep 45  # Wait for servers to load model

  run "python '$PROJECT_ROOT/synthesis/remediation_synthesizer.py' \
    --input '$PROJECT_ROOT/data/scanned' \
    --output '$PROJECT_ROOT/data/training/cve_remediation_pairs.jsonl' \
    --workers 32" 2>&1 | tee "$LOG_DIR/stage3_synth.log"

  kill $VLLM_PID 2>/dev/null || true
  log "Stage 3 complete."
fi

# Stage 4a: SFT Training
if [[ $FROM_STAGE -le 4 ]]; then
  log "--- Stage 4a: SFT Training ---"
  GPU_COUNT=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l || echo 0)
  log "Detected $GPU_COUNT GPUs"
  run "deepspeed --num_gpus=$GPU_COUNT '$PROJECT_ROOT/training/train.py' \
    --deepspeed '$PROJECT_ROOT/training/configs/deepspeed_zero3.json'" \
    2>&1 | tee "$LOG_DIR/stage4a_sft.log"
  log "SFT complete. Checkpoint at checkpoints/sft"
fi

# Stage 4b: RL Training (GRPO)
if [[ $FROM_STAGE -le 5 ]]; then
  log "--- Stage 4b: RL Training (GRPO) ---"
  # Build RL tasks from scanned data
  run "python '$PROJECT_ROOT/agents/validation_agent.py' \
    --build-rl \
    --scanned-dir '$PROJECT_ROOT/data/scanned' \
    --rl-output '$PROJECT_ROOT/data/rl/cve_scan_tasks.jsonl'"

  # Start sandbox for reward computation
  run "python '$PROJECT_ROOT/agents/validation_agent.py' --serve --port 8083 &"
  sleep 5

  GPU_COUNT=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l || echo 0)
  run "deepspeed --num_gpus=$GPU_COUNT '$PROJECT_ROOT/training/train_rl.py' \
    --deepspeed '$PROJECT_ROOT/training/configs/deepspeed_zero3.json'" \
    2>&1 | tee "$LOG_DIR/stage4b_rl.log"
  log "RL complete. Checkpoint at checkpoints/rl"
fi

# Stage 4c: DPO Training
if [[ $FROM_STAGE -le 6 ]]; then
  log "--- Stage 4c: DPO Training ---"
  GPU_COUNT=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l || echo 0)
  run "deepspeed --num_gpus=$GPU_COUNT '$PROJECT_ROOT/training/train_dpo.py' \
    --deepspeed '$PROJECT_ROOT/training/configs/deepspeed_zero3.json'" \
    2>&1 | tee "$LOG_DIR/stage4c_dpo.log"
  log "DPO complete. Final model at checkpoints/sealpatch-final"
fi

# Stage 5: Evaluation
if [[ $FROM_STAGE -le 7 ]]; then
  log "--- Stage 5: SealBench Evaluation ---"
  run "python '$PROJECT_ROOT/evaluation/sealbench.py' \
    --model-path './checkpoints/sealpatch-final' \
    --output-json '$PROJECT_ROOT/results/sealbench_results.json'" \
    2>&1 | tee "$LOG_DIR/stage5_eval.log"
  log "Evaluation complete. Results at results/sealbench_results.json"
fi

log "==============================="
log "SealPatch pipeline complete!"
log "==============================="
