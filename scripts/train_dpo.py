#!/usr/bin/env python3
"""Run real DPO alignment stage (no simulation mode)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import yaml

from training_pipeline_common import ROOT, ensure_dir, iter_jsonl, sha256_file, utc_ts, write_json


def _load_cfg(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Invalid YAML config: {path}")
    return data


def _validate_dpo(rows: list[dict]) -> tuple[int, int]:
    ok = 0
    bad = 0
    for r in rows:
        if all(isinstance(r.get(k), str) and r.get(k).strip() for k in ("prompt", "chosen", "rejected")):
            ok += 1
        else:
            bad += 1
    return ok, bad


def _resolve_torch_dtype(torch, cfg: dict):
    pref = str(cfg.get("precision", {}).get("dtype", "bfloat16")).strip().lower()
    if pref not in ("float32", "float16", "bfloat16"):
        pref = "bfloat16"
    return getattr(torch, pref)


def _iter_capped(path: Path, cap: int):
    for i, row in enumerate(iter_jsonl(path), start=1):
        if cap > 0 and i > cap:
            break
        yield row


def main() -> int:
    parser = argparse.ArgumentParser(description="DPO training runner")
    parser.add_argument(
        "--config",
        default=str(ROOT / "configs" / "training" / "dpo.yaml"),
        help="Config YAML path",
    )
    parser.add_argument("--base-model", default="", help="Optional override for base model id/path")
    parser.add_argument("--max-steps", type=int, default=0, help="Optional override for max train steps (>0)")
    parser.add_argument("--max-train-samples", type=int, default=0, help="Optional cap for train samples")
    args = parser.parse_args()

    cfg_path = Path(args.config).resolve()
    cfg = _load_cfg(cfg_path)
    run_id = f"dpo_{utc_ts()}"
    out_dir = ensure_dir(ROOT / cfg["outputs"]["adapters_dir"] / run_id)
    train_file = (ROOT / cfg["dataset"]["dpo_train"]).resolve()
    valid_file = (ROOT / cfg["dataset"]["dpo_valid"]).resolve()

    train_rows = list(_iter_capped(train_file, 0)) if train_file.exists() else []
    valid_rows = list(_iter_capped(valid_file, 0)) if valid_file.exists() else []
    ok_train, bad_train = _validate_dpo(train_rows)
    ok_valid, bad_valid = _validate_dpo(valid_rows)

    try:
        import torch  # type: ignore
        from datasets import Dataset  # type: ignore
        from transformers import AutoModelForCausalLM, AutoTokenizer  # type: ignore
        from trl import DPOConfig, DPOTrainer  # type: ignore
    except Exception as exc:
        raise RuntimeError(
            "DPO dependencies are required (transformers,datasets,trl,peft,accelerate). "
            "Install with: pip install -e \".[train]\""
        ) from exc

    base_model = args.base_model.strip() or str(cfg.get("base_model", "")).strip()
    if not base_model:
        raise ValueError("Base model is required (config base_model or --base-model).")

    if args.max_train_samples > 0:
        train_rows = list(_iter_capped(train_file, args.max_train_samples))
        valid_cap = max(1, args.max_train_samples // 5 or 1)
        valid_rows = list(_iter_capped(valid_file, valid_cap))

    tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    torch_dtype = _resolve_torch_dtype(torch, cfg)
    model = AutoModelForCausalLM.from_pretrained(
        base_model,
        torch_dtype=torch_dtype,
        device_map="auto" if torch.cuda.is_available() else None,
    )
    train_ds = Dataset.from_list(train_rows)
    valid_ds = Dataset.from_list(valid_rows)

    tcfg = cfg.get("training", {})
    requested_max_seq = int(tcfg.get("max_seq_length", 2048))
    tok_limit = int(getattr(tokenizer, "model_max_length", requested_max_seq) or requested_max_seq)
    if tok_limit > 1000000:
        tok_limit = requested_max_seq
    model_limit = int(getattr(model.config, "max_position_embeddings", tok_limit) or tok_limit)
    max_seq = max(8, min(requested_max_seq, tok_limit, model_limit))

    max_steps = args.max_steps if args.max_steps > 0 else int(tcfg.get("max_steps", -1))
    dpo_args = DPOConfig(
        output_dir=str(out_dir),
        beta=float(tcfg.get("beta", 0.1)),
        learning_rate=float(tcfg.get("learning_rate", 5e-5)),
        per_device_train_batch_size=int(tcfg.get("per_device_train_batch_size", 1)),
        gradient_accumulation_steps=int(tcfg.get("gradient_accumulation_steps", 8)),
        num_train_epochs=float(tcfg.get("num_train_epochs", 1)),
        max_steps=max_steps,
        logging_steps=1,
        report_to=[],
        save_strategy="no",
        max_length=max_seq,
        bf16=torch.cuda.is_available(),
        fp16=False,
        use_cpu=not torch.cuda.is_available(),
    )
    try:
        trainer = DPOTrainer(
            model=model,
            ref_model=None,
            args=dpo_args,
            train_dataset=train_ds,
            eval_dataset=valid_ds,
            processing_class=tokenizer,
        )
    except TypeError:
        trainer = DPOTrainer(
            model=model,
            ref_model=None,
            args=dpo_args,
            train_dataset=train_ds,
            eval_dataset=valid_ds,
            tokenizer=tokenizer,
        )
    train_output = trainer.train()
    trainer.model.save_pretrained(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))

    result = {
        "run_id": run_id,
        "mode": "dpo",
        "config_path": str(cfg_path),
        "base_model": base_model,
        "dataset": {
            "train": str(train_file),
            "valid": str(valid_file),
            "train_sha256": sha256_file(train_file) if train_file.exists() else "missing",
            "valid_sha256": sha256_file(valid_file) if valid_file.exists() else "missing",
            "train_ok_rows": ok_train,
            "train_bad_rows": bad_train,
            "valid_ok_rows": ok_valid,
            "valid_bad_rows": bad_valid,
            "train_rows": len(train_rows),
            "valid_rows": len(valid_rows),
        },
        "effective_max_seq_length": max_seq,
        "status": "trained",
        "train_metrics": dict(train_output.metrics),
    }
    write_json(out_dir / "training_result.json", result)
    print(json.dumps({"run_id": run_id, "status": result["status"], "out_dir": str(out_dir)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

