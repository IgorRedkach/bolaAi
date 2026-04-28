#!/usr/bin/env python3
"""Run real QLoRA/LoRA training for 0.5B-3B models with full activity logging.

Key improvements over previous version:
- ACTIVITY LOG: appending JSONL file (never overwrites) so full history is auditable
- ETA ESTIMATION: calculated from step rate × remaining steps
- VISIBLE PROGRESS: prints live progress lines to stdout at every step
- CPU-SAFE DEFAULTS: auto-detects CPU-only mode and adjusts dtype/optimizer/quantization
- LIVE STDOUT: all progress is printed so it's visible even from subprocess pipes
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from collections.abc import Iterable
from typing import Any, Callable

import yaml

from training_pipeline_common import ROOT, ensure_dir, iter_jsonl, sha256_file, utc_ts, write_json


HEARTBEAT_PATH = ROOT / "docs" / "retrain_live_heartbeat.json"
LOOP_STATUS_PATH = ROOT / "docs" / "retrain_loop_status.json"
ACTIVITY_LOG_PATH = ROOT / "docs" / "training_activity_log.jsonl"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append_activity(run_id: str, stage: str, **extra: Any) -> None:
    """Append a single event to the activity log (never overwrites — full history)."""
    entry: dict[str, Any] = {
        "ts_utc": _iso_now(),
        "run_id": run_id,
        "stage": stage,
    }
    entry.update(extra)
    ACTIVITY_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ACTIVITY_LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _write_heartbeat(run_id: str, stage: str, **extra: Any) -> None:
    """Overwrite heartbeat (latest state) AND append to activity log."""
    payload: dict[str, Any] = {
        "ts_utc": _iso_now(),
        "run_id": run_id,
        "stage": stage,
    }
    payload.update(extra)
    HEARTBEAT_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOOP_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    HEARTBEAT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    LOOP_STATUS_PATH.write_text(
        json.dumps(
            {
                "ts_utc": payload["ts_utc"],
                "state": stage,
                "run_id": run_id,
                "note": extra.get("note", ""),
                "progress": {k: v for k, v in extra.items() if k not in ("note",)},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    _append_activity(run_id, stage, **extra)


def _print_progress(msg: str) -> None:
    """Print to stdout with timestamp so it's visible even inside subprocess pipes."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    line = f"[TRAIN {ts}] {msg}"
    print(line, flush=True)


def _fmt_eta(seconds: float | None) -> str:
    if seconds is None or seconds < 0:
        return "unknown"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


def _load_cfg(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML config: {path}")
    return data


def _git_sha() -> str:
    head = ROOT / ".git" / "HEAD"
    if not head.exists():
        return "unknown"
    txt = head.read_text(encoding="utf-8").strip()
    if txt.startswith("ref: "):
        ref = ROOT / ".git" / txt.split(" ", 1)[1]
        return ref.read_text(encoding="utf-8").strip() if ref.exists() else "unknown"
    return txt


def _build_text(row: dict) -> str:
    return (
        "### Instruction\n"
        f"{row['instruction'].strip()}\n\n"
        "### Context\n"
        f"{row['context'].strip()}\n\n"
        "### Response\n"
        f"{row['target'].strip()}"
    )


def _resolve_target_modules(model, requested: list[str]) -> list[str]:
    names = [n for n, _ in model.named_modules()]
    resolved = []
    for mod in requested:
        if any(n.endswith(f".{mod}") or n == mod for n in names):
            resolved.append(mod)
    if resolved:
        return sorted(set(resolved))
    fallback_candidates = ("c_attn", "c_proj", "c_fc", "q_proj", "k_proj", "v_proj", "o_proj")
    for mod in fallback_candidates:
        if any(n.endswith(f".{mod}") or n == mod for n in names):
            resolved.append(mod)
    if resolved:
        return sorted(set(resolved))
    raise ValueError("Could not resolve any LoRA target modules for this base model.")


def _resolve_torch_dtype(torch, cfg: dict, use_cuda: bool):
    if not use_cuda:
        # Allow explicit bfloat16 on CPU to halve model RAM (12GB → 6GB for 3B).
        # LoRA adapter params are cast to float32 separately after get_peft_model().
        # Only enable when config has precision.dtype = bfloat16 AND allow_bf16_cpu: true.
        allow_bf16 = bool(cfg.get("allow_bf16_cpu", False))
        pref_cpu = str(cfg.get("precision", {}).get("dtype", "float32")).strip().lower()
        if allow_bf16 and pref_cpu == "bfloat16":
            return torch.bfloat16
        return torch.float32
    pref = str(
        cfg.get("precision", {}).get("dtype", cfg.get("quantization", {}).get("compute_dtype", "bfloat16"))
    ).strip().lower()
    if pref not in ("float32", "float16", "bfloat16"):
        pref = "bfloat16"
    return getattr(torch, pref)


def _enable_gradient_checkpointing_cpu(model) -> None:
    """Enable gradient checkpointing for CPU float32 training.

    On CUDA with 4-bit (BitsAndBytes), gradient checkpointing needs special hooks.
    On CPU with float32 (plain LoRA), it works with the standard transformers API.
    """
    try:
        model.gradient_checkpointing_enable()
        # Disable caching which conflicts with gradient checkpointing
        if hasattr(model, "config"):
            model.config.use_cache = False
        # For PEFT models, enable on the base model too
        if hasattr(model, "base_model") and hasattr(model.base_model, "model"):
            if hasattr(model.base_model.model, "gradient_checkpointing_enable"):
                model.base_model.model.gradient_checkpointing_enable()
    except Exception as exc:
        print(f"[TRAIN] Warning: gradient_checkpointing_enable failed: {exc}. Continuing without it.")
        print(f"[TRAIN] Memory usage will be higher. Consider reducing chunk_size_tokens if OOM.")


def _tokenize_with_chunks(
    rows: Iterable[dict],
    tokenizer,
    max_seq: int,
    chunk_size_tokens: int,
    chunk_overlap_tokens: int,
    max_total_chunks: int = 0,
    sample_packing: bool = False,
    eos_token_id: int | None = None,
    progress_cb: Callable[[int, int], None] | None = None,
) -> tuple[list[dict], int]:
    window = max(8, min(max_seq, chunk_size_tokens))
    overlap = max(0, min(chunk_overlap_tokens, window - 1))
    step = max(1, window - overlap)
    examples: list[dict] = []
    row_count = 0
    pack: list[int] = []
    text_chunk_chars = 24000

    def _iter_windows_for_text(text: str):
        token_buf: list[int] = []
        for start in range(0, len(text), text_chunk_chars):
            piece = text[start : start + text_chunk_chars]
            toks = tokenizer(piece, add_special_tokens=False, truncation=False)
            piece_ids = toks.get("input_ids", [])
            if not isinstance(piece_ids, list) or not piece_ids:
                continue
            token_buf.extend(piece_ids)
            while len(token_buf) >= window:
                yield token_buf[:window]
                token_buf = token_buf[step:]
        if token_buf:
            yield token_buf[:window]

    def _append_example(span_ids: list[int]) -> bool:
        examples.append({"input_ids": span_ids})
        if progress_cb and len(examples) % 25 == 0:
            progress_cb(row_count, len(examples))
        return max_total_chunks > 0 and len(examples) >= max_total_chunks

    for row in rows:
        row_count += 1
        text = _build_text(row)
        any_span = False
        for span in _iter_windows_for_text(text):
            any_span = True
            if len(span) < 8:
                continue
            if not sample_packing:
                if _append_example(span):
                    return examples, row_count
                continue

            ids = list(span)
            if eos_token_id is not None:
                ids = ids + [eos_token_id]
            if len(ids) >= window:
                if _append_example(ids[:window]):
                    return examples, row_count
                continue
            if not pack:
                pack = ids
                continue
            if len(pack) + len(ids) <= window:
                pack.extend(ids)
                continue
            if _append_example(pack):
                return examples, row_count
            pack = ids
        if not any_span:
            continue
        if progress_cb and row_count % 10 == 0:
            progress_cb(row_count, len(examples))
    if sample_packing and pack:
        _append_example(pack)
    return examples, row_count


def main() -> int:
    parser = argparse.ArgumentParser(description="QLoRA training runner with full activity logging")
    parser.add_argument(
        "--config",
        default=str(ROOT / "configs" / "training" / "qlora_1b3b.yaml"),
        help="Config YAML path",
    )
    parser.add_argument("--base-model", default="", help="Optional override for base model id/path")
    parser.add_argument("--max-steps", type=int, default=0, help="Optional override for max train steps (>0)")
    parser.add_argument("--max-train-samples", type=int, default=0, help="Optional cap for train samples")
    parser.add_argument(
        "--chunk-size-tokens",
        type=int,
        default=0,
        help="Token window size per training example (defaults to min(max_seq, 512 for CPU, 1024 for GPU))",
    )
    parser.add_argument(
        "--chunk-overlap-tokens",
        type=int,
        default=64,
        help="Overlap between chunk windows for long examples",
    )
    parser.add_argument("--max-train-token-chunks", type=int, default=0, help="Optional cap on tokenized train chunks")
    parser.add_argument("--max-valid-token-chunks", type=int, default=0, help="Optional cap on tokenized valid chunks")
    parser.add_argument(
        "--gradient-accumulation-steps",
        type=int,
        default=0,
        help="Optional override for gradient accumulation steps (>0)",
    )
    parser.add_argument(
        "--resume",
        default="",
        help=(
            "Path to a checkpoint directory to resume from, OR 'latest' to auto-detect the most "
            "recent checkpoint under models/adapters/. E.g.: --resume latest  "
            "OR: --resume models/adapters/qlora_20260410T145439Z/checkpoint-100"
        ),
    )
    args = parser.parse_args()

    cfg_path = Path(args.config).resolve()
    cfg = _load_cfg(cfg_path)

    # Resolve resume checkpoint path
    resume_ckpt: str | bool = False
    if args.resume:
        if args.resume.lower() == "latest":
            # Sort by modification time (not step number) so we don't accidentally
            # pick a completed run from a different model size / different run directory.
            candidates = sorted(
                ROOT.glob("models/adapters/qlora_*/checkpoint-*"),
                key=lambda p: p.stat().st_mtime,
            )
            if candidates:
                resume_ckpt = str(candidates[-1])
                print(f"[TRAIN] Auto-detected latest checkpoint: {resume_ckpt}")
            else:
                print("[TRAIN] WARNING: --resume=latest but no checkpoint found. Starting fresh.")
        else:
            resume_ckpt = str(Path(args.resume).resolve())
            if not Path(resume_ckpt).exists():
                print(f"[TRAIN] WARNING: checkpoint path not found: {resume_ckpt}. Starting fresh.")
                resume_ckpt = False

    run_id = f"qlora_{utc_ts()}"

    _print_progress(f"Starting training run: {run_id}")
    _print_progress(f"Config: {cfg_path}")
    _print_progress(f"Activity log: {ACTIVITY_LOG_PATH}")
    _write_heartbeat(run_id, "init", note="trainer bootstrapping")

    adapters_dir = ensure_dir(ROOT / cfg["outputs"]["adapters_dir"] / run_id)
    merged_dir = ensure_dir(ROOT / cfg["outputs"]["merged_dir"] / run_id)
    train_file = (ROOT / cfg["dataset"]["sft_train"]).resolve()
    valid_file = (ROOT / cfg["dataset"]["sft_valid"]).resolve()

    base_model = args.base_model.strip() or str(cfg.get("base_model", "")).strip()
    if not base_model:
        raise ValueError("Base model is required (config base_model or --base-model).")

    _print_progress(f"Loading tokenizer from: {base_model}")
    _write_heartbeat(run_id, "load_tokenizer", base_model=base_model)

    try:
        import torch  # type: ignore
        from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training  # type: ignore
        from transformers import (  # type: ignore
            AutoModelForCausalLM,
            AutoTokenizer,
            BitsAndBytesConfig,
            DataCollatorForLanguageModeling,
            Trainer,
            TrainerCallback,
            TrainingArguments,
        )
        from datasets import Dataset  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Training dependencies are required (transformers,datasets,peft,bitsandbytes,accelerate). "
            "Install with: pip install -e \".[train]\""
        ) from exc

    # Lower OOM kill priority for this process as much as permitted without root.
    # Unprivileged processes can only increase oom_score_adj (not decrease below 0),
    # but setting it explicitly to 0 removes the +100 default set by some cgroup configs.
    try:
        import pathlib as _pl
        _oom_path = _pl.Path("/proc/self/oom_score_adj")
        _cur = int(_oom_path.read_text().strip())
        if _cur > 0:
            _oom_path.write_text("0\n")
            _print_progress(f"OOM score adj lowered: {_cur} → 0 (training process protected)")
    except Exception as _e:
        _print_progress(f"OOM adj note: {_e}")

    use_cuda = torch.cuda.is_available()
    device_info = f"CUDA ({torch.cuda.get_device_name(0)})" if use_cuda else "CPU (no GPU detected)"
    _print_progress(f"Compute device: {device_info}")
    if not use_cuda:
        _print_progress("WARNING: CPU-only mode. Using float32 (or bf16 if allow_bf16_cpu=true). Max model: 0.5B recommended in fp32.")

    train_cap = args.max_train_samples if args.max_train_samples > 0 else 0
    valid_cap = max(1, args.max_train_samples // 5 or 1) if args.max_train_samples > 0 else 0

    tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    _print_progress("Tokenizer loaded.")

    torch_dtype = _resolve_torch_dtype(torch, cfg, use_cuda)
    use_4bit = use_cuda  # 4-bit quantization is CUDA-only
    quant_mode = "4bit_nf4" if use_4bit else "cpu_float32"
    quant_cfg = (
        BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type=str(cfg.get("quantization", {}).get("quant_type", "nf4")),
            bnb_4bit_compute_dtype=getattr(torch, str(cfg.get("quantization", {}).get("compute_dtype", "bfloat16"))),
            bnb_4bit_use_double_quant=True,
        )
        if use_4bit
        else None
    )

    # Free any garbage before loading the large model to maximise available RAM.
    import gc as _gc
    _gc.collect()
    _print_progress(f"Loading model: {base_model} (dtype={torch_dtype}, quantization={quant_mode})")
    _write_heartbeat(run_id, "load_model", note="loading base model", base_model=base_model, dtype=str(torch_dtype))
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        quantization_config=quant_cfg,
        torch_dtype=torch_dtype,
        device_map="auto" if use_cuda else None,
        low_cpu_mem_usage=True,
    )
    if use_4bit:
        model = prepare_model_for_kbit_training(model)
    model.config.use_cache = False
    _print_progress("Model loaded.")

    target_modules = _resolve_target_modules(model, list(cfg["lora"]["target_modules"]))
    lora_cfg = LoraConfig(
        r=int(cfg["lora"]["r"]),
        lora_alpha=int(cfg["lora"]["alpha"]),
        lora_dropout=float(cfg["lora"]["dropout"]),
        target_modules=target_modules,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_cfg)
    # When base model is bfloat16 (memory-saving CPU mode), cast only the trainable
    # LoRA adapter parameters to float32 so gradient accumulation stays numerically stable.
    if not use_cuda and torch_dtype != torch.float32:
        lora_fp32_count = 0
        for name, param in model.named_parameters():
            if param.requires_grad:
                param.data = param.data.to(torch.float32)
                lora_fp32_count += 1
        _print_progress(
            f"Mixed-precision CPU mode: base model kept in {torch_dtype}, "
            f"{lora_fp32_count} LoRA adapter tensors cast to float32 for stable gradients"
        )
    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    _print_progress(f"LoRA applied: {trainable:,} trainable / {total:,} total params ({100*trainable/total:.2f}%)")

    # Enable gradient checkpointing (works on CPU float32, saves 70-80% activation RAM)
    want_grad_ckpt = bool(cfg.get("training", {}).get("gradient_checkpointing", False))
    if want_grad_ckpt:
        _print_progress("Enabling gradient checkpointing (reduces activation RAM ~75%)")
        _enable_gradient_checkpointing_cpu(model)
    else:
        _print_progress("Gradient checkpointing: disabled")

    _write_heartbeat(
        run_id,
        "model_ready",
        resolved_target_modules=target_modules,
        quantization_mode=quant_mode,
        trainable_params=trainable,
        total_params=total,
        gradient_checkpointing=want_grad_ckpt,
    )

    requested_max_seq = int(cfg.get("training", {}).get("max_seq_length", 512 if not use_cuda else 2048))
    tok_limit = int(getattr(tokenizer, "model_max_length", requested_max_seq) or requested_max_seq)
    if tok_limit > 1000000:
        tok_limit = requested_max_seq
    model_limit = int(getattr(model.config, "max_position_embeddings", tok_limit) or tok_limit)
    max_seq = max(8, min(requested_max_seq, tok_limit, model_limit))
    default_chunk = 512 if not use_cuda else 1024
    chunk_size_tokens = args.chunk_size_tokens if args.chunk_size_tokens > 0 else min(max_seq, default_chunk)
    chunk_overlap_tokens = max(0, args.chunk_overlap_tokens)

    _print_progress(f"Tokenizing training data: {train_file}")
    _write_heartbeat(run_id, "tokenize_train_start", train_file=str(train_file))
    train_examples, train_row_count = _tokenize_with_chunks(
        (row for i, row in enumerate(iter_jsonl(train_file), start=1) if train_cap <= 0 or i <= train_cap),
        tokenizer,
        max_seq=max_seq,
        chunk_size_tokens=chunk_size_tokens,
        chunk_overlap_tokens=chunk_overlap_tokens,
        max_total_chunks=max(0, args.max_train_token_chunks),
        sample_packing=bool(cfg.get("training", {}).get("sample_packing", False)),
        eos_token_id=getattr(tokenizer, "eos_token_id", None),
        progress_cb=lambda rows, chunks: _write_heartbeat(
            run_id,
            "tokenize_train_progress",
            train_rows_seen=rows,
            train_chunks_built=chunks,
        ),
    )
    _print_progress(f"Train tokenized: {train_row_count} rows → {len(train_examples)} chunks (window={chunk_size_tokens})")
    _write_heartbeat(
        run_id,
        "tokenize_train_done",
        train_rows_seen=train_row_count,
        train_chunks_built=len(train_examples),
    )

    _print_progress(f"Tokenizing validation data: {valid_file}")
    _write_heartbeat(run_id, "tokenize_valid_start", valid_file=str(valid_file))
    valid_examples, valid_row_count = _tokenize_with_chunks(
        (row for i, row in enumerate(iter_jsonl(valid_file), start=1) if valid_cap <= 0 or i <= valid_cap),
        tokenizer,
        max_seq=max_seq,
        chunk_size_tokens=chunk_size_tokens,
        chunk_overlap_tokens=chunk_overlap_tokens,
        max_total_chunks=max(0, args.max_valid_token_chunks),
        sample_packing=bool(cfg.get("training", {}).get("sample_packing", False)),
        eos_token_id=getattr(tokenizer, "eos_token_id", None),
        progress_cb=lambda rows, chunks: _write_heartbeat(
            run_id,
            "tokenize_valid_progress",
            valid_rows_seen=rows,
            valid_chunks_built=chunks,
        ),
    )
    _print_progress(f"Valid tokenized: {valid_row_count} rows → {len(valid_examples)} chunks")
    _write_heartbeat(
        run_id,
        "tokenize_valid_done",
        valid_rows_seen=valid_row_count,
        valid_chunks_built=len(valid_examples),
    )

    train_ds = Dataset.from_list(train_examples)
    valid_ds = Dataset.from_list(valid_examples)
    data_collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    max_steps = args.max_steps if args.max_steps > 0 else int(cfg.get("training", {}).get("max_steps", 0))
    optim_name = str(cfg["training"].get("optimizer", "paged_adamw_8bit" if use_cuda else "adamw_torch"))
    if not use_cuda and optim_name.startswith("paged_"):
        optim_name = "adamw_torch"
    grad_accum = (
        args.gradient_accumulation_steps
        if args.gradient_accumulation_steps > 0
        else int(cfg["training"]["gradient_accumulation_steps"])
    )

    # Estimate total steps
    steps_per_epoch = max(1, len(train_examples) // grad_accum)
    num_epochs = float(cfg["training"].get("num_train_epochs", 1))
    estimated_steps = int(steps_per_epoch * num_epochs) if max_steps <= 0 else max_steps
    _print_progress(
        f"Training plan: {len(train_examples)} chunks, grad_accum={grad_accum}, "
        f"~{steps_per_epoch} steps/epoch × {num_epochs} epochs = ~{estimated_steps} steps"
    )
    if not use_cuda:
        _print_progress(f"CPU ETA estimate: ~{estimated_steps * 20}s–{estimated_steps * 40}s ({estimated_steps * 20 // 60}–{estimated_steps * 40 // 60} min)")

    train_args = TrainingArguments(
        output_dir=str(adapters_dir),
        per_device_train_batch_size=int(cfg["training"]["per_device_train_batch_size"]),
        gradient_accumulation_steps=grad_accum,
        learning_rate=float(cfg["training"]["learning_rate"]),
        num_train_epochs=num_epochs,
        max_steps=max_steps if max_steps > 0 else -1,
        logging_steps=1,
        save_strategy="steps",
        save_steps=int(cfg["training"].get("save_steps", 50)),
        save_total_limit=int(cfg["training"].get("save_total_limit", 3)),
        report_to=[],
        bf16=False,
        fp16=False,
        # gradient_checkpointing in TrainingArguments is separate from model.gradient_checkpointing_enable()
        # We call model.gradient_checkpointing_enable() manually above for CPU compatibility
        gradient_checkpointing=False,
        optim=optim_name,
        dataloader_pin_memory=use_cuda,
    )

    train_runtime_state: dict[str, Any] = {
        "global_step": 0,
        "max_steps": estimated_steps,
        "start_time": time.time(),
    }
    ticker_stop = threading.Event()

    class _HeartbeatCallback(TrainerCallback):
        def on_train_begin(self, args, state, control, **kwargs):  # type: ignore[override]
            train_runtime_state["global_step"] = int(state.global_step)
            train_runtime_state["max_steps"] = int(getattr(state, "max_steps", 0) or estimated_steps)
            train_runtime_state["start_time"] = time.time()
            _print_progress(f"Training begun. Max steps: {train_runtime_state['max_steps']}")
            _write_heartbeat(
                run_id,
                "train_begin",
                global_step=int(state.global_step),
                max_steps=train_runtime_state["max_steps"],
            )

        def on_log(self, args, state, control, logs=None, **kwargs):  # type: ignore[override]
            step = int(state.global_step)
            train_runtime_state["global_step"] = step
            max_s = train_runtime_state.get("max_steps", estimated_steps) or estimated_steps
            elapsed = time.time() - train_runtime_state.get("start_time", time.time())
            eta_sec: float | None = None
            if step > 0 and max_s > 0:
                rate = elapsed / step  # seconds per step
                remaining = max_s - step
                eta_sec = rate * remaining
                train_runtime_state["step_rate_sec"] = rate
                train_runtime_state["eta_sec"] = eta_sec

            payload: dict[str, Any] = {
                "global_step": step,
                "max_steps": max_s,
                "pct_done": round(100.0 * step / max_s, 1) if max_s > 0 else 0,
                "elapsed_sec": round(elapsed, 1),
                "eta_sec": round(eta_sec, 1) if eta_sec is not None else None,
                "eta_human": _fmt_eta(eta_sec),
            }
            if logs:
                for key in ("loss", "learning_rate", "epoch"):
                    if key in logs:
                        payload[key] = logs[key]
                        train_runtime_state[key] = logs[key]
            train_runtime_state.update(payload)
            _write_heartbeat(run_id, "train_progress", **payload)

            loss_str = f"loss={payload.get('loss', 'n/a'):.4f}" if isinstance(payload.get("loss"), float) else "loss=n/a"
            _print_progress(
                f"Step {step}/{max_s} ({payload['pct_done']}%) | {loss_str} | "
                f"elapsed={_fmt_eta(elapsed)} | ETA={payload['eta_human']}"
            )

        def on_train_end(self, args, state, control, **kwargs):  # type: ignore[override]
            step = int(state.global_step)
            elapsed = time.time() - train_runtime_state.get("start_time", time.time())
            train_runtime_state["global_step"] = step
            _print_progress(f"Training complete! Steps: {step}, elapsed: {_fmt_eta(elapsed)}")
            _write_heartbeat(run_id, "train_end", global_step=step, elapsed_sec=round(elapsed, 1))

    def _train_alive_ticker() -> None:
        while not ticker_stop.wait(30.0):
            step = train_runtime_state.get("global_step", 0)
            max_s = train_runtime_state.get("max_steps", estimated_steps) or estimated_steps
            eta_sec = train_runtime_state.get("eta_sec")
            elapsed = time.time() - train_runtime_state.get("start_time", time.time())
            _write_heartbeat(
                run_id,
                "train_alive",
                note="heartbeat tick — waiting for next trainer log event" if step == 0 else "training in progress",
                global_step=step,
                max_steps=max_s,
                pct_done=round(100.0 * step / max_s, 1) if max_s > 0 else 0,
                loss=train_runtime_state.get("loss"),
                epoch=train_runtime_state.get("epoch"),
                elapsed_sec=round(elapsed, 1),
                eta_sec=round(eta_sec, 1) if eta_sec is not None else None,
                eta_human=_fmt_eta(eta_sec),
            )

    trainer = Trainer(
        model=model,
        args=train_args,
        train_dataset=train_ds,
        eval_dataset=valid_ds,
        data_collator=data_collator,
        callbacks=[_HeartbeatCallback()],
    )
    _write_heartbeat(
        run_id,
        "train_start",
        train_rows=train_row_count,
        valid_rows=valid_row_count,
        train_chunks=len(train_examples),
        valid_chunks=len(valid_examples),
        estimated_steps=estimated_steps,
        base_model=base_model,
        device=device_info,
    )
    ticker = threading.Thread(target=_train_alive_ticker, daemon=True)
    ticker.start()
    if resume_ckpt:
        _print_progress(f"Resuming from checkpoint: {resume_ckpt}")
    try:
        train_output = trainer.train(resume_from_checkpoint=resume_ckpt if resume_ckpt else None)
    finally:
        ticker_stop.set()
        ticker.join(timeout=2.0)

    _print_progress("Saving adapter weights...")
    _write_heartbeat(run_id, "save_adapter_start")
    model.save_pretrained(str(adapters_dir))
    tokenizer.save_pretrained(str(adapters_dir))

    result = {
        "run_id": run_id,
        "mode": "qlora",
        "config_path": str(cfg_path),
        "base_model": base_model,
        "device": device_info,
        "dataset": {
            "train": str(train_file),
            "valid": str(valid_file),
            "train_sha256": sha256_file(train_file) if train_file.exists() else "missing",
            "valid_sha256": sha256_file(valid_file) if valid_file.exists() else "missing",
            "train_rows": train_row_count,
            "valid_rows": valid_row_count,
            "train_token_chunks": len(train_examples),
            "valid_token_chunks": len(valid_examples),
        },
        "lora": cfg.get("lora", {}),
        "training": cfg.get("training", {}),
        "git_sha": _git_sha(),
        "quantization_mode": quant_mode,
        "effective_max_seq_length": max_seq,
        "chunk_size_tokens": chunk_size_tokens,
        "chunk_overlap_tokens": chunk_overlap_tokens,
        "resolved_target_modules": target_modules,
        "status": "trained",
        "train_metrics": dict(train_output.metrics),
    }
    write_json(adapters_dir / "training_result.json", result)
    _print_progress(f"Training result saved: {adapters_dir / 'training_result.json'}")
    _write_heartbeat(
        run_id,
        "completed",
        status="trained",
        training_result=str(adapters_dir / "training_result.json"),
    )
    (merged_dir / "README.txt").write_text(
        "Real training completed. Merge adapter into base model in packaging stage.\n"
        "Use package_trained_model_for_ollama.py after adapter merge is completed.\n",
        encoding="utf-8",
    )
    result_summary = {
        "run_id": run_id,
        "status": result["status"],
        "adapters_dir": str(adapters_dir),
        "base_model": base_model,
        "device": device_info,
        "train_chunks": len(train_examples),
        "estimated_steps": estimated_steps,
        "actual_steps": result["train_metrics"].get("train_steps_per_second", "n/a"),
        "train_loss": result["train_metrics"].get("train_loss", "n/a"),
    }
    print(json.dumps(result_summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
