#!/usr/bin/env python3
"""Run real standard 16-bit LoRA training (no simulation mode)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from collections.abc import Iterable

import yaml

from training_pipeline_common import ROOT, ensure_dir, iter_jsonl, sha256_file, utc_ts, write_json


def _load_cfg(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML config: {path}")
    return data


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


def _resolve_torch_dtype(torch, cfg: dict):
    pref = str(cfg.get("precision", {}).get("dtype", "bfloat16")).strip().lower()
    if pref not in ("float32", "float16", "bfloat16"):
        pref = "bfloat16"
    return getattr(torch, pref)


def _tokenize_with_chunks(
    rows: Iterable[dict],
    tokenizer,
    max_seq: int,
    chunk_size_tokens: int,
    chunk_overlap_tokens: int,
    max_total_chunks: int = 0,
    sample_packing: bool = False,
    eos_token_id: int | None = None,
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
    if sample_packing and pack:
        _append_example(pack)
    return examples, row_count


def main() -> int:
    parser = argparse.ArgumentParser(description="LoRA16 training runner")
    parser.add_argument(
        "--config",
        default=str(ROOT / "configs" / "training" / "lora16_1b3b.yaml"),
        help="Config YAML path",
    )
    parser.add_argument("--base-model", default="", help="Optional override for base model id/path")
    parser.add_argument("--max-steps", type=int, default=0, help="Optional override for max train steps (>0)")
    parser.add_argument("--max-train-samples", type=int, default=0, help="Optional cap for train samples")
    parser.add_argument(
        "--chunk-size-tokens",
        type=int,
        default=0,
        help="Token window size per training example (defaults to min(max_seq, 1024))",
    )
    parser.add_argument(
        "--chunk-overlap-tokens",
        type=int,
        default=128,
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
    args = parser.parse_args()

    cfg_path = Path(args.config).resolve()
    cfg = _load_cfg(cfg_path)
    run_id = f"lora16_{utc_ts()}"
    adapters_dir = ensure_dir(ROOT / cfg["outputs"]["adapters_dir"] / run_id)
    train_file = (ROOT / cfg["dataset"]["sft_train"]).resolve()
    valid_file = (ROOT / cfg["dataset"]["sft_valid"]).resolve()

    base_model = args.base_model.strip() or str(cfg.get("base_model", "")).strip()
    if not base_model:
        raise ValueError("Base model is required (config base_model or --base-model).")

    try:
        import torch  # type: ignore
        from peft import LoraConfig, get_peft_model  # type: ignore
        from transformers import (  # type: ignore
            AutoModelForCausalLM,
            AutoTokenizer,
            DataCollatorForLanguageModeling,
            Trainer,
            TrainingArguments,
        )
        from datasets import Dataset  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "Training dependencies are required (transformers,datasets,peft,accelerate). "
            "Install with: pip install -e \".[train]\""
        ) from exc

    train_cap = args.max_train_samples if args.max_train_samples > 0 else 0
    valid_cap = max(1, args.max_train_samples // 5 or 1) if args.max_train_samples > 0 else 0

    tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    torch_dtype = _resolve_torch_dtype(torch, cfg)
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch_dtype,
        device_map="auto" if torch.cuda.is_available() else None,
        low_cpu_mem_usage=True,
    )
    model.config.use_cache = False
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
    requested_max_seq = int(cfg.get("training", {}).get("max_seq_length", 2048))
    tok_limit = int(getattr(tokenizer, "model_max_length", requested_max_seq) or requested_max_seq)
    if tok_limit > 1000000:
        tok_limit = requested_max_seq
    model_limit = int(getattr(model.config, "max_position_embeddings", tok_limit) or tok_limit)
    max_seq = max(8, min(requested_max_seq, tok_limit, model_limit))
    chunk_size_tokens = args.chunk_size_tokens if args.chunk_size_tokens > 0 else min(max_seq, 1024)
    chunk_overlap_tokens = max(0, args.chunk_overlap_tokens)

    train_examples, train_row_count = _tokenize_with_chunks(
        (row for i, row in enumerate(iter_jsonl(train_file), start=1) if train_cap <= 0 or i <= train_cap),
        tokenizer,
        max_seq=max_seq,
        chunk_size_tokens=chunk_size_tokens,
        chunk_overlap_tokens=chunk_overlap_tokens,
        max_total_chunks=max(0, args.max_train_token_chunks),
        sample_packing=bool(cfg.get("training", {}).get("sample_packing", False)),
        eos_token_id=getattr(tokenizer, "eos_token_id", None),
    )
    valid_examples, valid_row_count = _tokenize_with_chunks(
        (row for i, row in enumerate(iter_jsonl(valid_file), start=1) if valid_cap <= 0 or i <= valid_cap),
        tokenizer,
        max_seq=max_seq,
        chunk_size_tokens=chunk_size_tokens,
        chunk_overlap_tokens=chunk_overlap_tokens,
        max_total_chunks=max(0, args.max_valid_token_chunks),
        sample_packing=bool(cfg.get("training", {}).get("sample_packing", False)),
        eos_token_id=getattr(tokenizer, "eos_token_id", None),
    )
    train_ds = Dataset.from_list(train_examples)
    valid_ds = Dataset.from_list(valid_examples)
    data_collator = DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False)

    max_steps = args.max_steps if args.max_steps > 0 else int(cfg.get("training", {}).get("max_steps", 0))
    optim_name = str(cfg["training"].get("optimizer", "paged_adamw_8bit" if torch.cuda.is_available() else "adamw_torch"))
    if not torch.cuda.is_available() and optim_name.startswith("paged_"):
        optim_name = "adamw_torch"
    grad_accum = (
        args.gradient_accumulation_steps
        if args.gradient_accumulation_steps > 0
        else int(cfg["training"]["gradient_accumulation_steps"])
    )
    train_args = TrainingArguments(
        output_dir=str(adapters_dir),
        per_device_train_batch_size=int(cfg["training"]["per_device_train_batch_size"]),
        gradient_accumulation_steps=grad_accum,
        learning_rate=float(cfg["training"]["learning_rate"]),
        num_train_epochs=float(cfg["training"].get("num_train_epochs", 1)),
        max_steps=max_steps if max_steps > 0 else -1,
        logging_steps=1,
        save_strategy="no",
        report_to=[],
        bf16=torch.cuda.is_available(),
        fp16=False,
        gradient_checkpointing=bool(cfg["training"].get("gradient_checkpointing", True)),
        optim=optim_name,
        dataloader_pin_memory=torch.cuda.is_available(),
    )
    trainer = Trainer(
        model=model,
        args=train_args,
        train_dataset=train_ds,
        eval_dataset=valid_ds,
        data_collator=data_collator,
    )
    train_output = trainer.train()
    model.save_pretrained(str(adapters_dir))
    tokenizer.save_pretrained(str(adapters_dir))

    result = {
        "run_id": run_id,
        "mode": "lora16",
        "config_path": str(cfg_path),
        "base_model": base_model,
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
        "effective_max_seq_length": max_seq,
        "chunk_size_tokens": chunk_size_tokens,
        "chunk_overlap_tokens": chunk_overlap_tokens,
        "resolved_target_modules": target_modules,
        "status": "trained",
        "train_metrics": dict(train_output.metrics),
    }
    write_json(adapters_dir / "training_result.json", result)
    print(json.dumps({"run_id": run_id, "status": result["status"], "adapters_dir": str(adapters_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

