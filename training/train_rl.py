"""
Stage 2: CVE-Verified RL for SealPatch (GRPO)
Reward = CVE count reduction + CI green (behavior preserved).

Run:
  deepspeed --num_gpus=18 training/train_rl.py --deepspeed training/configs/deepspeed_zero3.json
"""

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import torch
from datasets import Dataset
from loguru import logger
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import GRPOConfig, GRPOTrainer

sys.path.insert(0, str(Path(__file__).parent.parent))
from synthesis.prompts import SEALPATCH_SYSTEM_PROMPT


@dataclass
class RLConfig:
    base_model: str = "Qwen/Qwen2.5-7B-Coder-Instruct"
    sft_adapter: str = "./checkpoints/sft"
    output_dir: str = "./checkpoints/rl"
    learning_rate: float = 5e-6
    num_train_epochs: int = 1
    per_device_train_batch_size: int = 1
    gradient_accumulation_steps: int = 8
    num_generations: int = 8
    sandbox_api_url: str = "http://localhost:8080"
    rl_tasks_path: str = "./data/rl/cve_scan_tasks.jsonl"
    logging_steps: int = 10
    save_steps: int = 100
    wandb_project: str = "sealpatch-rl"


def compute_cve_reward(patch_text: str, task_meta: dict, sandbox_url: str) -> float:
    """
    Apply patch, rescan with Grype, run smoke test.
    Reward based on CVE count reduction + CI green.
    """
    import re
    import requests

    fix_match = re.search(r"<fix>(.*?)</fix>", patch_text, re.DOTALL)
    if not fix_match:
        return 0.0
    diff = fix_match.group(1).strip()
    if not diff or len(diff) < 10:
        return 0.0

    try:
        resp = requests.post(
            f"{sandbox_url}/execute",
            json={
                "diff": diff,
                "repo": task_meta.get("repo"),
                "before_sha": task_meta.get("before_sha"),
                "language": task_meta.get("language"),
                "scan_type": "grype",
                "run_smoke_test": True,
            },
            timeout=300,
        )
        result = resp.json()
    except Exception as e:
        logger.debug(f"Sandbox error: {e}")
        return 0.0

    cve_before = task_meta.get("critical_before", 0) + task_meta.get("high_before", 0)
    cve_after = result.get("critical_after", cve_before) + result.get(
        "high_after", cve_before
    )
    ci_green = result.get("smoke_test_passed", False)

    if not ci_green:
        return 0.0  # Behavior broken — no reward

    if cve_after >= cve_before:
        return 0.0  # CI green but no CVE reduction — no reward for no-op patches
    elif cve_after > 0:
        reduction = (cve_before - cve_after) / cve_before
        return 0.5 + reduction * 0.3  # Partial reduction
    else:
        # All CRITICAL/HIGH eliminated + CI green
        reward = 1.0
        # Minimality bonus
        diff_lines = len(
            [
                l
                for l in diff.split("\n")
                if l.startswith(("+", "-")) and not l.startswith(("---", "+++"))
            ]
        )
        if diff_lines <= 5:
            reward = min(reward + 0.1, 1.1)
        elif diff_lines > 50:
            reward = max(reward - 0.1, 0.0)
        return reward


def build_reward_fn(config: RLConfig):
    def reward_fn(
        prompts: list[str],
        completions: list[str],
        **kwargs,
    ) -> list[float]:
        # completions is a flat list of strings: num_prompts * num_generations entries.
        # prompts is a flat list of the same length (each prompt repeated num_generations times).
        metadata_list = kwargs.get("metadata", [])
        rewards = []
        for i, completion in enumerate(completions):
            meta = metadata_list[i % len(metadata_list)] if metadata_list else {}
            r = compute_cve_reward(completion, meta, config.sandbox_api_url)
            rewards.append(r)
        mean_reward = sum(rewards) / len(rewards) if rewards else 0.0
        logger.info(f"Rewards: mean={mean_reward:.3f}")
        return rewards

    return reward_fn


def load_rl_dataset(path: str) -> Dataset:
    examples = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ex = json.loads(line)
            except Exception:
                continue

            if not all(k in ex for k in ("dockerfile_before", "cve_ids", "repo")):
                continue

            prompt = (
                f"<|im_start|>system\n{SEALPATCH_SYSTEM_PROMPT}<|im_end|>\n"
                f"<|im_start|>user\n"
                f"Repository: {ex.get('repo', 'unknown')}\n"
                f"Scan: {ex.get('critical_before', 0)} CRITICAL, {ex.get('high_before', 0)} HIGH\n"
                f"CVEs: {', '.join(ex.get('cve_ids', []))}\n"
                f"Artifact:\n{ex.get('dockerfile_before', '')[:4000]}\n\n"
                f"Remediate all CVEs.\n"
                f"<|im_end|>\n<|im_start|>assistant\n"
            )
            ex["prompt"] = prompt
            ex["metadata"] = {
                "repo": ex.get("repo"),
                "before_sha": ex.get("before_sha"),
                "language": ex.get("language", "python"),
                "critical_before": ex.get("critical_before", 0),
                "high_before": ex.get("high_before", 0),
            }
            examples.append(ex)

    logger.info(f"RL dataset: {len(examples)} CVE scan tasks")
    return Dataset.from_list(examples)


def train(config: RLConfig):
    logger.info("Loading base model + SFT adapter for GRPO...")
    base = AutoModelForCausalLM.from_pretrained(
        config.base_model, torch_dtype=torch.bfloat16, use_cache=False
    )
    tokenizer = AutoTokenizer.from_pretrained(config.base_model)
    tokenizer.pad_token = tokenizer.eos_token
    model = PeftModel.from_pretrained(base, config.sft_adapter, is_trainable=True)
    model.enable_input_require_grads()

    dataset = load_rl_dataset(config.rl_tasks_path)
    reward_fn = build_reward_fn(config)

    grpo_cfg = GRPOConfig(
        output_dir=config.output_dir,
        learning_rate=config.learning_rate,
        num_train_epochs=config.num_train_epochs,
        per_device_train_batch_size=config.per_device_train_batch_size,
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        num_generations=config.num_generations,
        logging_steps=config.logging_steps,
        save_steps=config.save_steps,
        bf16=True,
        gradient_checkpointing=True,
        deepspeed="training/configs/deepspeed_zero3.json",
        report_to="wandb" if os.environ.get("WANDB_API_KEY") else "none",
        run_name="sealpatch-grpo",
    )

    trainer = GRPOTrainer(
        model=model,
        processing_class=tokenizer,
        args=grpo_cfg,
        train_dataset=dataset,
        reward_funcs=[reward_fn],
    )
    logger.info("Starting CVE-RL GRPO training...")
    trainer.train()
    trainer.save_model(config.output_dir)
    tokenizer.save_pretrained(config.output_dir)
    logger.info(f"GRPO complete. Saved to {config.output_dir}")


if __name__ == "__main__":
    import typer

    def main(
        sft_adapter: str = "./checkpoints/sft", output_dir: str = "./checkpoints/rl"
    ):
        train(RLConfig(sft_adapter=sft_adapter, output_dir=output_dir))

    typer.run(main)
