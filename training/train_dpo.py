"""
Stage 3: DPO for SealPatch
Prefers surgical minimal CVE fixes over blanket dependency upgrades.

Run:
  deepspeed --num_gpus=18 training/train_dpo.py --deepspeed training/configs/deepspeed_zero3.json
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
from trl import DPOConfig, DPOTrainer

sys.path.insert(0, str(Path(__file__).parent.parent))
from synthesis.prompts import SEALPATCH_SYSTEM_PROMPT


@dataclass
class DPOCfg:
    base_model: str = "Qwen/Qwen2.5-7B-Coder-Instruct"
    rl_adapter: str = "./checkpoints/rl"
    output_dir: str = "./checkpoints/sealpatch-final"
    learning_rate: float = 1e-6
    num_train_epochs: int = 1
    per_device_train_batch_size: int = 1
    gradient_accumulation_steps: int = 8
    beta: float = 0.1
    max_length: int = 8192
    max_prompt_length: int = 4096
    dpo_pairs_path: str = "./data/training/dpo_pairs.jsonl"
    logging_steps: int = 10
    save_steps: int = 100


def load_dpo_dataset(path: str) -> Dataset:
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
            prompt = ex.get("prompt", "")
            chosen = ex.get("chosen_fix") or ex.get("chosen", "")
            rejected = ex.get("rejected_fix") or ex.get("rejected", "")
            if not (prompt and chosen and rejected) or chosen == rejected:
                continue
            examples.append({
                "prompt": (
                    f"<|im_start|>system\n{SEALPATCH_SYSTEM_PROMPT}<|im_end|>\n"
                    f"<|im_start|>user\n{prompt}<|im_end|>\n<|im_start|>assistant\n"
                ),
                "chosen": chosen + "<|im_end|>",
                "rejected": rejected + "<|im_end|>",
            })
    logger.info(f"DPO dataset: {len(examples)} pairs")
    return Dataset.from_list(examples)


def train(config: DPOCfg):
    tokenizer = AutoTokenizer.from_pretrained(config.base_model)
    tokenizer.pad_token = tokenizer.eos_token
    base = AutoModelForCausalLM.from_pretrained(
        config.base_model, torch_dtype=torch.bfloat16, use_cache=False
    )
    if not Path(config.rl_adapter).exists():
        raise FileNotFoundError(
            f"RL adapter not found: {config.rl_adapter}\n"
            "Run Stage 2 (train_rl.py) before Stage 3 (train_dpo.py)"
        )
    model = PeftModel.from_pretrained(base, config.rl_adapter, is_trainable=True)
    model.enable_input_require_grads()

    dataset = load_dpo_dataset(config.dpo_pairs_path)
    split = dataset.train_test_split(test_size=0.05, seed=42)

    dpo_cfg = DPOConfig(
        output_dir=config.output_dir,
        learning_rate=config.learning_rate,
        num_train_epochs=config.num_train_epochs,
        per_device_train_batch_size=config.per_device_train_batch_size,
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        beta=config.beta, max_length=config.max_length, max_prompt_length=config.max_prompt_length,
        eval_strategy="steps",
        eval_steps=config.save_steps,
        logging_steps=config.logging_steps, save_steps=config.save_steps,
        bf16=True, gradient_checkpointing=True,
        deepspeed="training/configs/deepspeed_zero3.json",
        report_to="wandb" if os.environ.get("WANDB_API_KEY") else "none",
        run_name="sealpatch-dpo",
    )

    trainer = DPOTrainer(
        model=model, ref_model=None, processing_class=tokenizer,
        args=dpo_cfg, train_dataset=split["train"], eval_dataset=split["test"],
    )
    logger.info("Starting DPO training for SealPatch...")
    trainer.train()
    trainer.save_model(config.output_dir)
    tokenizer.save_pretrained(config.output_dir)
    logger.info(f"DPO complete. Final model at {config.output_dir}")


if __name__ == "__main__":
    import typer
    def main(rl_adapter: str = "./checkpoints/rl", output_dir: str = "./checkpoints/sealpatch-final"):
        train(DPOCfg(rl_adapter=rl_adapter, output_dir=output_dir))
    typer.run(main)
