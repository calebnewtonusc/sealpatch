"""
SealPatch — Remediation Synthesizer
Synthesizes CVE-fix pairs from OSV/NVD advisories and builds DPO preference pairs.

Usage:
  python synthesis/remediation_synthesizer.py --concurrency 32
  python synthesis/remediation_synthesizer.py --dpo-mode
"""

import asyncio
import json
import os
import random
import time
from pathlib import Path

import httpx
import typer
from loguru import logger

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
VLLM_URLS = os.environ.get("VLLM_URLS", "http://localhost:8001").split(",")
VLLM_API_KEY = os.environ.get("VLLM_API_KEY", "")

SYNTHESIS_SYSTEM_PROMPT = """\
You are a Docker security remediation expert. Given a CVE advisory, generate:
1. A realistic Dockerfile or lockfile snippet that contains this vulnerability
2. The minimal fix that eliminates the CVE while preserving application behavior
3. The CVE category (BASE_IMAGE_CVE, APP_DEP_CVE, RUNTIME_CVE, BUILD_TOOL_CVE)

Output JSON:
{
  "cve_id": "<CVE ID>",
  "ecosystem": "<Python|npm|Go|Java|Ruby|Rust>",
  "cve_category": "<category>",
  "dockerfile_before": "<realistic Dockerfile or lockfile content>",
  "dockerfile_after": "<content after minimal fix>",
  "fix_diff": "<unified diff of the fix>",
  "fix_explanation": "<one sentence: why this fix eliminates the CVE>",
  "behavior_impact": "none|minimal|moderate",
  "is_dev_only": false
}
"""

DPO_SYSTEM_PROMPT = """\
You are generating DPO preference pairs for a CVE remediation model.
Given a CVE, generate TWO different fixes:
1. CHOSEN: The minimal surgical fix (exact version bump, targeted change)
2. REJECTED: An over-engineered fix (blanket upgrade, unnecessary changes)

The chosen fix should:
- Change as few lines as possible
- Target exactly the CVE-affected package/image
- Not change other unrelated dependencies

The rejected fix should be plausible but worse:
- Change many unrelated dependencies
- Upgrade the base image entirely when only one package needs updating
- Make broader changes than necessary

Output JSON:
{
  "cve_id": "<CVE ID>",
  "prompt": "<Dockerfile or lockfile content with the CVE>",
  "chosen_fix": "<minimal targeted diff>",
  "rejected_fix": "<over-engineered diff>",
  "chosen_rationale": "<why chosen is better>",
  "rejected_flaw": "<what makes rejected worse>"
}
"""


async def synthesize_from_advisory(
    client: httpx.AsyncClient,
    advisory: dict,
    backend: str,
    vllm_url: str,
) -> dict | None:
    """Synthesize a training pair from a CVE advisory."""
    cve_id = advisory.get("cve_id") or advisory.get("ghsa_id") or advisory.get("id", "")
    package_name = advisory.get("package_name", "")
    vulnerable_range = advisory.get("vulnerable_version_range", "")
    fixed_version = advisory.get("patched_versions") or advisory.get("fixed_version") or ""
    ecosystem = advisory.get("ecosystem", "Python")
    severity = advisory.get("severity", "HIGH")
    summary = advisory.get("summary", "")[:300]

    if not package_name or not cve_id:
        return None

    prompt = (
        f"CVE Advisory:\n"
        f"ID: {cve_id}\n"
        f"Package: {package_name} ({ecosystem})\n"
        f"Vulnerable versions: {vulnerable_range}\n"
        f"Fixed version: {fixed_version}\n"
        f"Severity: {severity}\n"
        f"Summary: {summary}\n\n"
        f"Generate a realistic Dockerfile/lockfile training example with this CVE and its minimal fix."
    )

    messages = [
        {"role": "system", "content": SYNTHESIS_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    try:
        if backend == "vllm":
            resp = await client.post(
                f"{vllm_url}/v1/chat/completions",
                headers={"Authorization": f"Bearer {VLLM_API_KEY}"},
                json={"model": "Qwen/Qwen2.5-72B-Instruct", "messages": messages,
                      "max_tokens": 1024, "temperature": 0.7},
                timeout=90.0,
            )
            resp.raise_for_status()
            text = resp.json()["choices"][0]["message"]["content"].strip()
        else:
            from anthropic import AsyncAnthropic
            aclient = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
            msg = await aclient.messages.create(
                model="claude-haiku-4-5", max_tokens=1024,
                system=SYNTHESIS_SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            text = msg.content[0].text.strip()

        start = text.find("{")
        end = text.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        data = json.loads(text[start:end + 1])

        required = ["dockerfile_before", "dockerfile_after", "fix_diff", "cve_category"]
        if not all(k in data for k in required):
            return None

        data["id"] = f"synth_{cve_id}_{random.randint(1000, 9999)}"
        data["source"] = "synthesized"
        data["has_fix"] = True
        data["behavior_preserved"] = True
        data["verified_scan"] = False
        return data

    except Exception as e:
        logger.debug(f"Synthesis error ({cve_id}): {e}")
        return None


async def run_synthesis(
    output_dir: Path,
    backend: str,
    concurrency: int,
    advisories_dir: Path,
):
    """Run bulk synthesis from CVE advisories."""
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "synthesized_cve_pairs.jsonl"

    # Load advisories
    advisories = []
    for jf in advisories_dir.rglob("*.jsonl"):
        with open(jf) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        advisories.append(json.loads(line))
                    except Exception:
                        pass

    # Filter for actionable advisories (have package + fix version)
    advisories = [
        a for a in advisories
        if a.get("package_name") and (a.get("fixed_version") or a.get("patched_versions"))
    ]

    random.shuffle(advisories)
    logger.info(f"Synthesizing from {len(advisories)} CVE advisories...")

    semaphore = asyncio.Semaphore(concurrency)
    vllm_urls = VLLM_URLS if backend == "vllm" else [""]
    total_written = 0

    with open(output_file, "a") as out:
        async with httpx.AsyncClient() as client:
            async def synth_with_sem(advisory):
                async with semaphore:
                    url = random.choice(vllm_urls)
                    return await synthesize_from_advisory(client, advisory, backend, url)

            batch_size = concurrency * 4
            for i in range(0, len(advisories), batch_size):
                batch = advisories[i:i + batch_size]
                results = await asyncio.gather(*[synth_with_sem(a) for a in batch])
                for r in results:
                    if r:
                        out.write(json.dumps(r) + "\n")
                        total_written += 1

                if i % (batch_size * 5) == 0:
                    logger.info(f"  Progress: {i}/{len(advisories)} | Written: {total_written}")

    logger.info(f"Synthesis complete: {total_written} pairs → {output_file}")


def build_dpo_pairs(
    classified_dir: Path,
    output_file: Path,
    backend: str,
    n_pairs: int,
):
    """Build DPO preference pairs: surgical fix vs. over-engineered fix."""
    import anthropic

    all_records = []
    for jf in classified_dir.rglob("*.jsonl"):
        with open(jf) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        all_records.append(json.loads(line))
                    except Exception:
                        pass

    random.shuffle(all_records)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    written = 0

    with open(output_file, "w") as out:
        for rec in all_records[:n_pairs]:
            if not rec.get("dockerfile_before") or not rec.get("fix_diff"):
                continue

            prompt_text = (
                f"Dockerfile/lockfile with CVE:\n{rec.get('dockerfile_before', '')[:2000]}\n\n"
                f"CVE: {rec.get('cve_id', 'unknown')}\n"
                f"Generate the minimal security fix."
            )

            # Chosen: the actual minimal fix
            chosen = rec["fix_diff"]

            # Generate rejected: over-engineered alternative
            rejected_prompt = (
                f"Generate a WORSE but plausible security fix that is over-engineered:\n"
                f"- Upgrades unnecessary packages\n"
                f"- Changes the base image entirely when just one package needs updating\n"
                f"- Makes broader changes than necessary\n\n"
                f"Context:\n{rec.get('dockerfile_before', '')[:1000]}\n"
                f"CVE: {rec.get('cve_id', '')}\n"
                f"Output ONLY the diff."
            )

            try:
                if backend == "claude":
                    import anthropic
                    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                    msg = client.messages.create(
                        model="claude-haiku-4-5", max_tokens=512,
                        messages=[{"role": "user", "content": rejected_prompt}],
                    )
                    rejected = msg.content[0].text.strip()
                    time.sleep(0.5)  # Rate limit: Anthropic API
                else:
                    url = random.choice(VLLM_URLS)
                    resp = httpx.post(
                        f"{url}/v1/chat/completions",
                        headers={"Authorization": f"Bearer {VLLM_API_KEY}"},
                        json={"model": "Qwen/Qwen2.5-72B-Instruct",
                              "messages": [{"role": "user", "content": rejected_prompt}],
                              "max_tokens": 512, "temperature": 0.9},
                        timeout=60.0,
                    )
                    resp.raise_for_status()
                    rejected = resp.json()["choices"][0]["message"]["content"].strip()
            except Exception:
                continue

            if not rejected or len(rejected) < 20 or rejected == chosen:
                continue

            dpo = {
                "id": rec.get("id", "") + "_dpo",
                "prompt": prompt_text,
                "chosen": chosen,
                "rejected": rejected,
                "cve_category": rec.get("cve_category"),
                "source": "dpo_synthetic",
            }
            out.write(json.dumps(dpo) + "\n")
            written += 1

    logger.info(f"DPO pairs: {written} written to {output_file}")


app = typer.Typer()


@app.command()
def main(
    output_dir: Path = typer.Option(Path("data/synthesized"), help="Output directory"),
    advisories_dir: Path = typer.Option(Path("data/cve_db"), help="CVE advisory directory"),
    backend: str = typer.Option("claude", help="Backend: claude | vllm"),
    concurrency: int = typer.Option(32, help="Concurrent synthesis workers"),
    dpo_mode: bool = typer.Option(False, "--dpo-mode"),
    classified_dir: Path = typer.Option(Path("data/classified")),
    dpo_output: Path = typer.Option(Path("data/training/dpo_pairs.jsonl")),
    n_pairs: int = typer.Option(50000),
):
    """Synthesize CVE remediation training pairs from CVE advisories."""
    if dpo_mode:
        build_dpo_pairs(classified_dir, dpo_output, backend, n_pairs)
    else:
        asyncio.run(run_synthesis(output_dir, backend, concurrency, advisories_dir))


if __name__ == "__main__":
    app()
