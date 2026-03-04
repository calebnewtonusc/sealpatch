# SealPatch — 18× A6000 GPU Setup

## Hardware Configuration

| Resource | Spec |
|----------|------|
| GPUs | 18× NVIDIA A6000 (48GB VRAM each) |
| Total VRAM | 864GB |
| RAM | 512GB+ |
| Storage | 2TB NVMe SSD (CVE DB + scan results + checkpoints) |
| Network | 100Gbps InfiniBand |

---

## Environment Setup

```bash
# 1. Python 3.11+
python3 --version

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install security scanners
# Grype (for CVE scanning)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Trivy (for container scanning)
wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux_64bit.tar.gz
tar -xf trivy_Linux_64bit.tar.gz -C /usr/local/bin trivy

# Verify scanner installations
grype --version
trivy --version

# 4. Configure environment
cp .env.example .env
# Fill in: GITHUB_TOKEN, ANTHROPIC_API_KEY, NVD_API_KEY, WANDB_API_KEY

# 5. Sync CVE databases (run once, takes ~2h)
python discovery/cve_database.py --sync-all

# 6. Validate full environment
bash scripts/check_env.sh
```

---

## Training Commands

### Stage 1: SFT (7 hours)

```bash
deepspeed --num_gpus=18 training/train.py \
  --deepspeed training/configs/deepspeed_zero3.json
```

### Stage 2: CVE-RL / GRPO (4 hours)

```bash
# Start scan executor pool first
python agents/validation_agent.py --executor-pool 8 &
sleep 15

deepspeed --num_gpus=18 training/train_rl.py \
  --deepspeed training/configs/deepspeed_zero3.json
```

### Stage 3: DPO (2 hours)

```bash
deepspeed --num_gpus=18 training/train_dpo.py \
  --deepspeed training/configs/deepspeed_zero3.json
```

---

## Synthesis Setup

```bash
# 4 vLLM instances for Qwen2.5-72B synthesis
CUDA_VISIBLE_DEVICES=0,1,2,3 bash scripts/start_vllm.sh --port 8001 &
CUDA_VISIBLE_DEVICES=4,5,6,7 bash scripts/start_vllm.sh --port 8002 &
CUDA_VISIBLE_DEVICES=8,9,10,11 bash scripts/start_vllm.sh --port 8003 &
CUDA_VISIBLE_DEVICES=12,13,14,15 bash scripts/start_vllm.sh --port 8004 &
```

---

## Common Issues

**Issue**: Grype scan fails during GRPO reward computation
- Grype requires network access to update vulnerability DB during first run
- Pre-cache: `grype db update` before starting GRPO training
- GRPO sandboxes run with `--network=none` — pre-download DB first

**Issue**: Docker build fails in synthesis validation
- Ensure Docker daemon is running: `systemctl start docker`
- For GPU-enabled sandboxes: install `nvidia-container-toolkit`

**Issue**: NVD API rate limited
- NVD free tier: 5 requests/30s. Get a free API key at nvd.nist.gov
- Set `NVD_API_KEY` in `.env` for 50 requests/30s

**Issue**: OOM during GRPO
- CVE scan sandboxes are CPU-bound but need ~8GB RAM each
- Reduce `--executor-pool` if OOM: `python agents/validation_agent.py --executor-pool 4`
