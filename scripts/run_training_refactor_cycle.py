#!/usr/bin/env python3
"""Run the refactored QLoRA/LoRA training cycle end-to-end."""

from __future__ import annotations

import argparse
import shlex
import subprocess
from pathlib import Path

from training_pipeline_common import ROOT


def _run(cmd: list[str], *, allow_fail: bool = False) -> int:
    """Run a command with live stdout streaming (no silent piping)."""
    printable = " ".join(shlex.quote(c) for c in cmd)
    ts = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%H:%M:%S")
    print(f"\n[CYCLE {ts}] $ {printable}", flush=True)
    proc = subprocess.run(cmd, cwd=str(ROOT))
    if proc.returncode != 0 and not allow_fail:
        raise RuntimeError(f"Command failed ({proc.returncode}): {printable}")
    return proc.returncode


def _latest_run_dir(prefix: str) -> Path:
    base = ROOT / "models" / "adapters"
    runs = sorted([p for p in base.glob(f"{prefix}_*") if p.is_dir()])
    if not runs:
        raise FileNotFoundError(f"No adapter runs found for prefix={prefix} in {base}")
    return runs[-1]


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute refactored training cycle")
    parser.add_argument("--base-model", default="", help="Override base model for all training stages")
    parser.add_argument("--max-steps", type=int, default=0, help="Override max train steps for train scripts")
    parser.add_argument("--max-train-samples", type=int, default=0, help="Optional cap for train rows")
    parser.add_argument("--max-train-token-chunks", type=int, default=0, help="Optional cap for tokenized train chunks")
    parser.add_argument("--max-valid-token-chunks", type=int, default=0, help="Optional cap for tokenized valid chunks")
    parser.add_argument("--chunk-size-tokens", type=int, default=0, help="Chunk window size for SFT train scripts")
    parser.add_argument("--chunk-overlap-tokens", type=int, default=128, help="Chunk overlap for SFT train scripts")
    parser.add_argument(
        "--track",
        choices=["qlora", "lora16", "both"],
        default="both",
        help="Which training track(s) to run",
    )
    parser.add_argument(
        "--split-input",
        default="",
        help="Optional JSONL input for build_training_splits.py (defaults to reviewing_training.jsonl when present)",
    )
    parser.add_argument(
        "--skip-promote-ollama",
        action="store_true",
        help="Skip adapter merge and Ollama promotion after training",
    )
    parser.add_argument("--model-name", default="bola-analyzer", help="Target Ollama model name for promotion")
    args = parser.parse_args()

    _run(["python", "scripts/build_absence_logic_dataset.py"])
    _run(["python", "scripts/build_toolcall_schema_set.py"])
    split_input = args.split_input.strip()
    if not split_input:
        preferred = ROOT / "data" / "training" / "reviewing_training.jsonl"
        fallback = ROOT / "data" / "training" / "bola_training.jsonl"
        split_input = str(preferred if preferred.exists() else fallback)
    _run(["python", "scripts/build_training_splits.py", "--input", split_input])
    _run(["python", "scripts/distill_teacher_outputs.py"])
    _run(["python", "scripts/distill_with_mentor.py"])

    shared_args: list[str] = []
    sft_only_args: list[str] = []
    sft_chunk_args: list[str] = []
    if args.base_model:
        shared_args.extend(["--base-model", args.base_model])
    if args.max_steps > 0:
        shared_args.extend(["--max-steps", str(args.max_steps)])
    if args.max_train_samples > 0:
        shared_args.extend(["--max-train-samples", str(args.max_train_samples)])
    if args.max_train_token_chunks > 0:
        sft_only_args.extend(["--max-train-token-chunks", str(args.max_train_token_chunks)])
    if args.max_valid_token_chunks > 0:
        sft_only_args.extend(["--max-valid-token-chunks", str(args.max_valid_token_chunks)])
    if args.chunk_size_tokens > 0:
        sft_chunk_args.extend(["--chunk-size-tokens", str(args.chunk_size_tokens)])
    if args.chunk_overlap_tokens > 0:
        sft_chunk_args.extend(["--chunk-overlap-tokens", str(args.chunk_overlap_tokens)])

    latest_run: Path | None = None
    if args.track in ("qlora", "both"):
        _run(["python", "scripts/train_qlora_unsloth.py", *shared_args, *sft_only_args, *sft_chunk_args])
        latest_run = _latest_run_dir("qlora")
    if args.track in ("lora16", "both"):
        _run(["python", "scripts/train_lora16.py", *shared_args, *sft_only_args, *sft_chunk_args])
        if args.track == "lora16":
            latest_run = _latest_run_dir("lora16")

    _run(["python", "scripts/train_dpo.py", *shared_args], allow_fail=True)
    _run(["python", "scripts/train_rlvr_toolexec.py"], allow_fail=True)
    _run(["python", "scripts/eval_security_agent_model.py"], allow_fail=True)

    if not args.skip_promote_ollama:
        if latest_run is None:
            raise RuntimeError("No adapter run available for Ollama promotion")
        _run(
            [
                "python",
                "scripts/package_trained_model_for_ollama.py",
                "--run-dir",
                str(latest_run),
                "--model-name",
                args.model_name,
            ]
        )

    print("Refactor cycle completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

