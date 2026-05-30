"""
build_external_datasets.py — Extract and combine external prompt injection datasets

Sources (all license-compatible with Apache 2.0):
  1. Garak in-the-wild jailbreaks (666 prompts, Apache 2.0) — NVIDIA/garak
  2. Lakera/gandalf_ignore_instructions (777 prompts, MIT) — HuggingFace
  3. deepset/prompt-injections (203 attacks + 343 safe, Apache 2.0) — HuggingFace
  4. TensorTrust (already have 400, kept separate)

Output: benchmarks/external_attacks.json — unified format compatible with multi_model_benchmark.py
"""

import json
import sys
from pathlib import Path

BENCHMARKS_DIR = Path(__file__).parent
OUTPUT_FILE = BENCHMARKS_DIR / "external_attacks.json"


def load_garak_inthewild():
    """Load 665 in-the-wild jailbreak prompts from Garak's resources."""
    try:
        import garak
        garak_path = Path(garak.__path__[0]) / "resources" / "inthewild_jailbreak_llms.txt"
        with open(garak_path) as f:
            prompts = [line.strip() for line in f if line.strip()]
        print(f"  Garak in-the-wild: {len(prompts)} prompts")
        return [{"source": "garak-inthewild", "text": p} for p in prompts]
    except Exception as e:
        print(f"  Garak FAILED: {e}")
        return []


def load_gandalf():
    """Load 777 ignore-instructions prompts from Lakera's Gandalf game."""
    try:
        from datasets import load_dataset
        ds = load_dataset("Lakera/gandalf_ignore_instructions", split="train")
        prompts = [row["text"] for row in ds if row["text"] and row["text"].strip()]
        print(f"  Gandalf: {len(prompts)} prompts")
        return [{"source": "gandalf", "text": p} for p in prompts]
    except Exception as e:
        print(f"  Gandalf FAILED: {e}")
        return []


def load_deepset():
    """Load 203 injection prompts + 343 safe prompts from deepset."""
    try:
        from datasets import load_dataset
        ds = load_dataset("deepset/prompt-injections", split="train")
        attacks = [row["text"] for row in ds if row["label"] == 1 and row["text"].strip()]
        safe = [row["text"] for row in ds if row["label"] == 0 and row["text"].strip()]
        print(f"  deepset: {len(attacks)} attacks, {len(safe)} safe")
        attack_entries = [{"source": "deepset-attack", "text": p} for p in attacks]
        safe_entries = [{"source": "deepset-safe", "text": p} for p in safe]
        return attack_entries, safe_entries
    except Exception as e:
        print(f"  deepset FAILED: {e}")
        return [], []


def deduplicate(entries):
    """Remove exact-duplicate prompts (case-sensitive)."""
    seen = set()
    unique = []
    for entry in entries:
        text = entry["text"].strip()
        if text not in seen:
            seen.add(text)
            unique.append(entry)
    return unique


def main():
    print("Building external attack datasets...\n")

    # Collect all attacks
    all_attacks = []
    all_safe = []

    print("Loading sources:")
    all_attacks.extend(load_garak_inthewild())
    all_attacks.extend(load_gandalf())
    deepset_attacks, deepset_safe = load_deepset()
    all_attacks.extend(deepset_attacks)
    all_safe.extend(deepset_safe)

    # Deduplicate
    before = len(all_attacks)
    all_attacks = deduplicate(all_attacks)
    safe_before = len(all_safe)
    all_safe = deduplicate(all_safe)
    print(f"\nDedup: {before} -> {len(all_attacks)} attacks, {safe_before} -> {len(all_safe)} safe")

    # Add IDs
    for i, entry in enumerate(all_attacks):
        entry["id"] = i
        entry["expected_safe"] = False

    for i, entry in enumerate(all_safe):
        entry["id"] = f"safe-{i}"
        entry["expected_safe"] = True

    # Source breakdown
    sources = {}
    for entry in all_attacks:
        src = entry["source"]
        sources[src] = sources.get(src, 0) + 1
    print("\nAttack sources:")
    for src, count in sorted(sources.items()):
        print(f"  {src}: {count}")

    # Save attacks
    output = {
        "metadata": {
            "description": "Combined external prompt injection datasets for Little Canary benchmarking",
            "sources": {
                "garak-inthewild": {
                    "name": "NVIDIA Garak in-the-wild jailbreaks",
                    "license": "Apache 2.0",
                    "url": "https://github.com/NVIDIA/garak",
                },
                "gandalf": {
                    "name": "Lakera Gandalf ignore-instructions",
                    "license": "MIT",
                    "url": "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
                },
                "deepset-attack": {
                    "name": "deepset prompt-injections (attack split)",
                    "license": "Apache 2.0",
                    "url": "https://huggingface.co/datasets/deepset/prompt-injections",
                },
                "deepset-safe": {
                    "name": "deepset prompt-injections (safe split)",
                    "license": "Apache 2.0",
                    "url": "https://huggingface.co/datasets/deepset/prompt-injections",
                },
            },
            "total_attacks": len(all_attacks),
            "total_safe": len(all_safe),
        },
        "attacks": all_attacks,
        "safe": all_safe,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nSaved to {OUTPUT_FILE}")
    print(f"  {len(all_attacks)} attacks + {len(all_safe)} safe = {len(all_attacks) + len(all_safe)} total")


if __name__ == "__main__":
    main()
