#!/usr/bin/env python3
"""Memory-efficient LoRA adapter merge using float16.

Merges a trained QLoRA adapter into the base model using float16 (not float32)
to keep peak RAM under ~13GB on a 30GB system without GPU.

Output: models/merged/bola-har-merged/  (exact path required by Dockerfile)
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADAPTER_DIR = ROOT / "models" / "adapters" / "qlora_20260426T171128Z"
OUTPUT_DIR = ROOT / "models" / "merged" / "bola-har-merged"

import torch
from peft import PeftModel  # type: ignore
from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore

def main() -> int:
    print(f"[merge] Adapter : {ADAPTER_DIR}")
    print(f"[merge] Output  : {OUTPUT_DIR}")
    print(f"[merge] dtype   : float16 (memory-efficient)")

    if OUTPUT_DIR.exists() and any(OUTPUT_DIR.iterdir()):
        print(f"[merge] Output already exists and non-empty — skipping merge.")
        return 0

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    base_model_id = "Qwen/Qwen2.5-Coder-3B-Instruct"
    print(f"[merge] Loading base model {base_model_id} in float16...")
    base = AutoModelForCausalLM.from_pretrained(
        base_model_id,
        torch_dtype=torch.float16,
        device_map=None,          # CPU only
        low_cpu_mem_usage=True,
    )
    print(f"[merge] Base model loaded.")

    print(f"[merge] Loading adapter from {ADAPTER_DIR}...")
    model = PeftModel.from_pretrained(base, str(ADAPTER_DIR), torch_dtype=torch.float16)
    print(f"[merge] Merging adapter weights...")
    merged = model.merge_and_unload()
    print(f"[merge] Merge complete. Saving to {OUTPUT_DIR}...")
    merged.save_pretrained(str(OUTPUT_DIR))

    tok_source = ADAPTER_DIR if (ADAPTER_DIR / "tokenizer_config.json").is_file() else base_model_id
    tok = AutoTokenizer.from_pretrained(str(tok_source), use_fast=True)
    tok.save_pretrained(str(OUTPUT_DIR))

    files = list(OUTPUT_DIR.iterdir())
    total_mb = sum(f.stat().st_size for f in files if f.is_file()) / 1024 / 1024
    print(f"[merge] Saved {len(files)} files, total {total_mb:.0f} MB")
    print(f"[merge] DONE: {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
