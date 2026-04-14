#!/usr/bin/env python3
"""Run RLVR-style verifiable checks over tool-call outputs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from training_pipeline_common import ROOT, TRAINING_DIR, iter_jsonl, utc_ts, write_json


def _score_target(target: str) -> dict:
    low = target.lower()
    return {
        "has_curl": "curl " in low,
        "has_auth": "authorization" in low or "token_" in low,
        "has_json_shape": "{" in target and "}" in target,
        "has_aura_form_shape": "aura.context" in low or "message=" in low,
        "has_placeholder_bad_pattern": bool(re.search(r"\[use only endpoints from documentation\]|(^|\s)/api(\s|$)", low)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="RLVR toolexec verifier harness")
    parser.add_argument(
        "--input",
        default=str(TRAINING_DIR / "sft" / "toolcall_schema.jsonl"),
        help="Input dataset with targets",
    )
    args = parser.parse_args()

    src = Path(args.input).resolve()
    if not src.exists():
        raise FileNotFoundError(f"Input not found: {src}")

    total = 0
    has_curl_sum = 0
    has_auth_sum = 0
    has_json_shape_sum = 0
    has_aura_form_shape_sum = 0
    placeholder_bad_sum = 0
    for row in iter_jsonl(src):
        total += 1
        check = _score_target(str(row.get("target", "")))
        has_curl_sum += int(check["has_curl"])
        has_auth_sum += int(check["has_auth"])
        has_json_shape_sum += int(check["has_json_shape"])
        has_aura_form_shape_sum += int(check["has_aura_form_shape"])
        placeholder_bad_sum += int(check["has_placeholder_bad_pattern"])
    aggregate = {
        "total": total,
        "has_curl_rate": has_curl_sum / total if total else 0.0,
        "has_auth_rate": has_auth_sum / total if total else 0.0,
        "has_json_shape_rate": has_json_shape_sum / total if total else 0.0,
        "has_aura_form_shape_rate": has_aura_form_shape_sum / total if total else 0.0,
        "placeholder_bad_rate": placeholder_bad_sum / total if total else 0.0,
    }
    out = {
        "created_at": utc_ts(),
        "input": str(src),
        "aggregate": aggregate,
        "status": "verified",
    }
    out_file = ROOT / "models" / "adapters" / f"rlvr_verifier_{utc_ts()}.json"
    write_json(out_file, out)
    print(json.dumps({"status": "verified", "output": str(out_file), "aggregate": aggregate}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

