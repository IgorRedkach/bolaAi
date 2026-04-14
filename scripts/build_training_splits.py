#!/usr/bin/env python3
"""Build SFT/DPO/EVAL splits from generated training corpus."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from training_pipeline_common import (
    TRAINING_DIR,
    append_jsonl_row,
    ensure_dir,
    iter_jsonl,
    sha256_file,
    utc_ts,
    write_json,
)


def _normalize_row(row: dict, idx: int) -> dict:
    # Folder-set manifest compatibility path.
    context_path = str(row.get("context_path", "")).strip()
    expected_response_path = str(row.get("expected_response_path", "")).strip()
    analysis_explanation_path = str(row.get("analysis_explanation_path", "")).strip()
    if context_path and expected_response_path and analysis_explanation_path:
        cp = Path(context_path)
        rp = Path(expected_response_path)
        ep = Path(analysis_explanation_path)
        if not (cp.is_file() and rp.is_file() and ep.is_file()):
            raise ValueError(f"Row {idx} references missing folder-set files")
        context = cp.read_text(encoding="utf-8")
        expected_response = rp.read_text(encoding="utf-8").strip()
        analysis_explanation = ep.read_text(encoding="utf-8").strip()
        return {
            "instruction": "Analyze the artifact context and provide a grounded security response.",
            "context": context,
            "target": f"{expected_response}\n\n## Analysis Explanation\n{analysis_explanation}",
        }

    # Backward-compatible path for legacy rows.
    if all(isinstance(row.get(k), str) and row.get(k).strip() for k in ("instruction", "context", "target")):
        return {
            "instruction": row["instruction"].strip(),
            "context": row["context"].strip(),
            "target": row["target"].strip(),
        }

    # New schema path with explicit expected_response + analysis_explanation.
    artifacts_context = str(row.get("artifacts_context", "")).strip()
    expected_response = str(row.get("expected_response", "")).strip()
    analysis_explanation = str(row.get("analysis_explanation", "")).strip()
    if not artifacts_context or not expected_response or not analysis_explanation:
        raise ValueError(
            f"Row {idx} missing required new-schema fields "
            "('artifacts_context', 'expected_response', 'analysis_explanation')"
        )
    instruction = "Analyze the artifact context and provide a grounded security response."
    target = f"{expected_response}\n\n## Analysis Explanation\n{analysis_explanation}"
    return {
        "instruction": instruction,
        "context": artifacts_context,
        "target": target,
    }


def _extract_paths(text: str) -> list[str]:
    raw = re.findall(r"/[A-Za-z0-9._{}\\-]+(?:/[A-Za-z0-9._{}\\-]+)+", text or "")
    seen: set[str] = set()
    out: list[str] = []
    for p in raw:
        p = p.rstrip(".,;:")
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def _to_dpo_rows(row: dict) -> list[dict]:
    prompt = f"{row['instruction']}\n\nContext:\n{row['context']}"
    chosen = row["target"].strip()
    context_low = row["context"].lower()
    instruction_low = row["instruction"].lower()
    paths = _extract_paths(row["context"])
    endpoint_hint = paths[0] if paths else "/API"

    rejected_rows: list[dict] = []

    # Hard negative 1: placeholder and generic path artifacts.
    rejected_rows.append(
        {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": (
                "Potential issue exists.\n"
                "Use this endpoint: [use only endpoints from documentation]\n"
                f"curl -X GET \"https://api.example.com{('/contract' if endpoint_hint != '/contract' else '/API')}\" "
                "-H \"Authorization: Bearer token\""
            ),
        }
    )

    # Hard negative 2: invalid verification logic (single-user / auth-only check).
    rejected_rows.append(
        {
            "prompt": prompt,
            "chosen": chosen,
            "rejected": (
                f"Test only one request on {endpoint_hint} with a valid token and confirm 200.\n"
                "If 401 appears without token, report authorization vulnerability.\n"
                "No need to compare two authenticated users."
            ),
        }
    )

    # Hard negative 3: protocol hallucination for REST-only contexts.
    mentions_graphql = "graphql" in context_low
    mentions_soql = "soql" in context_low or "salesforce" in context_low or "aura" in context_low
    asks_graphql = "graphql" in instruction_low
    asks_soql = "soql" in instruction_low
    if (asks_graphql and not mentions_graphql) or (asks_soql and not mentions_soql):
        rejected_rows.append(
            {
                "prompt": prompt,
                "chosen": chosen,
                "rejected": (
                    "Use GraphQL and SOQL checks regardless of artifact.\n"
                    "Run mutation deleteDocument(id:\"victim\") and "
                    "SELECT Id, Name FROM Opportunity WITH SECURITY_ENFORCED.\n"
                    "These protocol checks are always applicable."
                ),
            }
        )

    return rejected_rows


def _score(seed: int, idx: int, row: dict) -> float:
    key = f"{seed}|{idx}|{row.get('instruction','')}|{row.get('context','')[:200]}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    value = int(digest, 16)
    maxv = float(16**16 - 1)
    return value / maxv if maxv else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description="Create training splits from bola_training.jsonl")
    parser.add_argument(
        "--input",
        default=str(TRAINING_DIR / "bola_training.jsonl"),
        help="Input JSONL path",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--sft-valid-ratio", type=float, default=0.1)
    parser.add_argument("--eval-ratio", type=float, default=0.1)
    args = parser.parse_args()

    src = Path(args.input).resolve()
    sft_train_path = TRAINING_DIR / "sft" / "train.jsonl"
    sft_valid_path = TRAINING_DIR / "sft" / "valid.jsonl"
    dpo_train_path = TRAINING_DIR / "dpo" / "train.jsonl"
    dpo_valid_path = TRAINING_DIR / "dpo" / "valid.jsonl"
    eval_path = TRAINING_DIR / "eval" / "holdout.jsonl"
    for p in (sft_train_path, sft_valid_path, dpo_train_path, dpo_valid_path, eval_path):
        ensure_dir(p.parent)

    total = 0
    sft_train_count = 0
    sft_valid_count = 0
    eval_count = 0
    dpo_train_count = 0
    dpo_valid_count = 0
    skipped_invalid_rows = 0
    valid_cut = args.eval_ratio + ((1.0 - args.eval_ratio) * args.sft_valid_ratio)

    with (
        sft_train_path.open("w", encoding="utf-8") as sft_train_f,
        sft_valid_path.open("w", encoding="utf-8") as sft_valid_f,
        dpo_train_path.open("w", encoding="utf-8") as dpo_train_f,
        dpo_valid_path.open("w", encoding="utf-8") as dpo_valid_f,
        eval_path.open("w", encoding="utf-8") as eval_f,
    ):
        for i, raw in enumerate(iter_jsonl(src), start=1):
            try:
                row = _normalize_row(raw, i)
            except ValueError as exc:
                skipped_invalid_rows += 1
                print(f"[split-skip] row={i} reason={exc}")
                continue
            total += 1
            s = _score(args.seed, i, row)
            if s < args.eval_ratio:
                append_jsonl_row(eval_f, row)
                eval_count += 1
                continue
            if s < valid_cut:
                append_jsonl_row(sft_valid_f, row)
                sft_valid_count += 1
            else:
                append_jsonl_row(sft_train_f, row)
                sft_train_count += 1
            for dpo_row in _to_dpo_rows(row):
                ds = _score(args.seed + 17, i, dpo_row)
                if ds < 0.9:
                    append_jsonl_row(dpo_train_f, dpo_row)
                    dpo_train_count += 1
                else:
                    append_jsonl_row(dpo_valid_f, dpo_row)
                    dpo_valid_count += 1

    meta = {
        "created_at": utc_ts(),
        "source": str(src),
        "source_sha256": sha256_file(src),
        "seed": args.seed,
        "split_strategy": "hash_streaming",
        "counts": {
            "total": total,
            "skipped_invalid_rows": skipped_invalid_rows,
            "sft_train": sft_train_count,
            "sft_valid": sft_valid_count,
            "dpo_train": dpo_train_count,
            "dpo_valid": dpo_valid_count,
            "eval_holdout": eval_count,
        },
    }
    write_json(TRAINING_DIR / "split_manifest.json", meta)

    print("Built training splits:")
    for k, v in meta["counts"].items():
        print(f"  - {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

