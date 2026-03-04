#!/usr/bin/env bash
# SealPatch — vLLM Synthesis Server Startup
# Launches 4 vLLM instances of Qwen2.5-72B-Instruct for training data synthesis.
# GPUs 0-3, 4-7, 8-11, 12-15 each host a 4-GPU tensor-parallel instance.
# Each server generates CVE remediation pair suggestions for the synthesizer.

set -euo pipefail

MODEL="${VLLM_MODEL:-Qwen/Qwen2.5-72B-Instruct}"
LOG_DIR="${LOG_DIR:-./logs}"
BASE_PORT=8001

mkdir -p "$LOG_DIR"

echo "[vLLM] Starting 4 synthesis server instances for $MODEL"
echo "[vLLM] Ports: 8001, 8002, 8003, 8004"
echo "[vLLM] GPU layout: 0-3 / 4-7 / 8-11 / 12-15"

for i in 0 1 2 3; do
	PORT=$((BASE_PORT + i))
	GPU_START=$((i * 4))
	GPU_END=$((GPU_START + 3))
	GPUS="${GPU_START},${GPU_START+1},$((GPU_START + 2)),$((GPU_START + 3))"
	# Build comma-separated GPU list
	GPUS=$(seq $GPU_START $GPU_END | tr '\n' ',' | sed 's/,$//')

	echo "[vLLM] Instance $((i + 1)): port $PORT, GPUs $GPUS"
	CUDA_VISIBLE_DEVICES="$GPUS" python -m vllm.entrypoints.openai.api_server \
		--model "$MODEL" \
		--port $PORT \
		--host 0.0.0.0 \
		--tensor-parallel-size 4 \
		--dtype bfloat16 \
		--max-model-len 16384 \
		--served-model-name "sealpatch-synth" \
		--gpu-memory-utilization 0.92 \
		--disable-log-requests \
		>"$LOG_DIR/vllm_instance_${i}.log" 2>&1 &

	echo "[vLLM] Instance $((i + 1)) PID: $!"
done

echo ""
echo "[vLLM] All 4 instances started. Waiting 60s for model load..."
sleep 60

# Health check each instance
ALL_OK=true
for i in 0 1 2 3; do
	PORT=$((BASE_PORT + i))
	if curl -sf "http://localhost:$PORT/health" >/dev/null 2>&1; then
		echo "[vLLM] Instance $((i + 1)) (port $PORT): HEALTHY"
	else
		echo "[vLLM] Instance $((i + 1)) (port $PORT): NOT READY (check logs/vllm_instance_${i}.log)"
		ALL_OK=false
	fi
done

if [[ "$ALL_OK" == "true" ]]; then
	echo ""
	echo "[vLLM] All synthesis servers ready."
	echo "[vLLM] Set VLLM_BASE_URLS=http://localhost:8001,http://localhost:8002,http://localhost:8003,http://localhost:8004"
else
	echo ""
	echo "[vLLM] Some servers not ready. Check logs and retry."
	exit 1
fi

# Keep script alive to maintain process group
wait
