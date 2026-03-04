"""
Stage 1: SFT for SealPatch
Fine-tunes Qwen2.5-7B-Coder-Instruct on ~400k CVE remediation pairs.
LoRA rank 64, DeepSpeed ZeRO-3, 18× A6000.

Run:
  deepspeed --num_gpus=18 training/train.py --deepspeed training/configs/deepspeed_zero3.json
"""

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import torch
from datasets import Dataset
from loguru import logger
from peft import LoraConfig, TaskType, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import SFTConfig, SFTTrainer

sys.path.insert(0, str(Path(__file__).parent.parent))
from synthesis.prompts import SEALPATCH_SYSTEM_PROMPT


@dataclass
class SFTConfig_SP:
    base_model: str = "Qwen/Qwen2.5-7B-Coder-Instruct"
    output_dir: str = "./checkpoints/sft"
    num_train_epochs: int = 3
    per_device_train_batch_size: int = 2
    gradient_accumulation_steps: int = 4
    learning_rate: float = 2e-4
    warmup_ratio: float = 0.03
    lr_scheduler_type: str = "cosine"
    max_seq_length: int = 16384
    lora_r: int = 64
    lora_alpha: int = 128
    lora_dropout: float = 0.05
    training_data: str = "./data/training/cve_remediation_pairs.jsonl"
    logging_steps: int = 25
    save_steps: int = 500
    wandb_project: str = "sealpatch-sft"


def format_example(example: dict) -> str:
    """Format a CVE remediation pair as a training example."""
    repo = example.get("repo", "unknown")
    language = example.get("ecosystem", example.get("language", "unknown"))
    dockerfile_before = example.get("dockerfile_before", "")
    scan_before = example.get("scan_before", {})
    cve_category = example.get("cve_category", "APP_DEP_CVE")
    cve_id = example.get("cve_id", "")
    fix_diff = example.get("fix_diff", "")
    fix_explanation = example.get("fix_explanation", "")
    is_dev_only = example.get("is_dev_only", False)
    behavior_preserved = example.get("behavior_preserved", True)

    cves = scan_before.get("cves", [cve_id] if cve_id else [])
    critical = scan_before.get("critical", 0)
    high = scan_before.get("high", 0)

    user_msg = (
        f"Repository: {repo} ({language})\n"
        f"Scan results: {critical} CRITICAL, {high} HIGH CVEs\n"
        f"CVEs found: {', '.join(cves[:5]) if cves else cve_id}\n\n"
        f"Artifact (Dockerfile/lockfile):\n{dockerfile_before[:4000]}\n\n"
        f"Categorize each CVE and generate the minimal fix."
    )

    suppress_note = f"[SUPPRESSED — dev-only, does not affect production]" if is_dev_only else ""

    assistant_msg = (
        f"<categorize>\n"
        f"{cve_id or 'CVE-UNKNOWN'}: {cve_category} — "
        f"{'suppress' if is_dev_only else 'fix'} — {fix_explanation or 'see fix below'}\n"
        f"</categorize>\n"
        f"<fix>\n"
        f"{fix_diff if not is_dev_only else '(no fix needed — dev-only dependency)'}\n"
        f"</fix>\n"
        f"<suppress>\n"
        f"{suppress_note}\n"
        f"</suppress>\n"
        f"<validate>\n"
        f"Run: grype . --fail-on critical --fail-on high\n"
        f"Expected: 0 CRITICAL, 0 HIGH after applying fix.\n"
        f"</validate>"
    )

    return (
        f"<|im_start|>system\n{SEALPATCH_SYSTEM_PROMPT}<|im_end|>\n"
        f"<|im_start|>user\n{user_msg}<|im_end|>\n"
        f"<|im_start|>assistant\n{assistant_msg}<|im_end|>"
    )


def load_training_data(config: SFTConfig_SP) -> Dataset:
    data_path = Path(config.training_data)
    if not data_path.exists():
        raise FileNotFoundError(
            f"Training data not found: {data_path}\n"
            "Run: python pipeline.py --stage discovery && python pipeline.py --stage synthesis"
        )

    examples = []
    with open(data_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ex = json.loads(line)
                if ex.get("fix_diff") or ex.get("is_dev_only"):
                    examples.append(ex)
            except Exception:
                pass

    logger.info(f"Loaded {len(examples)} CVE remediation pairs")
    formatted = [{"text": format_example(ex)} for ex in examples]
    return Dataset.from_list(formatted)


def train(config: SFTConfig_SP):
    logger.info(f"Loading base model: {config.base_model}")
    tokenizer = AutoTokenizer.from_pretrained(config.base_model)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    model = AutoModelForCausalLM.from_pretrained(
        config.base_model, torch_dtype=torch.bfloat16, use_cache=False
    )
    lora_config = LoraConfig(
        r=config.lora_r, lora_alpha=config.lora_alpha, lora_dropout=config.lora_dropout,
        bias="none", task_type=TaskType.CAUSAL_LM,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    dataset = load_training_data(config)
    split = dataset.train_test_split(test_size=0.1, seed=42)

    sft_cfg = SFTConfig(
        output_dir=config.output_dir,
        num_train_epochs=config.num_train_epochs,
        per_device_train_batch_size=config.per_device_train_batch_size,
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        learning_rate=config.learning_rate,
        warmup_ratio=config.warmup_ratio,
        lr_scheduler_type=config.lr_scheduler_type,
        max_seq_length=config.max_seq_length,
        eval_strategy="steps",
        eval_steps=config.save_steps,
        logging_steps=config.logging_steps,
        save_steps=config.save_steps,
        bf16=True, gradient_checkpointing=True,
        deepspeed="training/configs/deepspeed_zero3.json",
        report_to="wandb" if os.environ.get("WANDB_API_KEY") else "none",
        run_name="sealpatch-sft",
        dataset_text_field="text",
        packing=False,
    )

    trainer = SFTTrainer(
        model=model, processing_class=tokenizer,
        train_dataset=split["train"], eval_dataset=split["test"],
        args=sft_cfg,
    )
    logger.info("Starting SFT training for SealPatch...")
    trainer.train()
    trainer.save_model(config.output_dir)
    tokenizer.save_pretrained(config.output_dir)
    logger.info(f"SFT complete. Saved to {config.output_dir}")


if __name__ == "__main__":
    import typer
    def main(output_dir: str = "./checkpoints/sft"):
        train(SFTConfig_SP(output_dir=output_dir))
    typer.run(main)
