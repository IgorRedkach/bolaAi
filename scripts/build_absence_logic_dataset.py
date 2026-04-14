#!/usr/bin/env python3
"""Generate explicit 'logic of absence' training records."""

from __future__ import annotations

import argparse
from pathlib import Path

from training_pipeline_common import TRAINING_DIR, utc_ts, write_json, write_jsonl


def _record(idx: int, endpoint: str, missing_check: str, secure: str, vulnerable: str) -> dict:
    context = (
        f"Artifact excerpt:\n"
        f"- Endpoint: {endpoint}\n"
        "- Auth: Bearer token required\n"
        f"- Missing invariant: {missing_check}\n"
    )
    target = (
        f"Observation: No documented check for {missing_check} on `{endpoint}`.\n"
        "Verification:\n"
        "1. Run the same object request with AUTH_TOKEN_1 (authorized principal).\n"
        "2. Repeat with AUTH_TOKEN_2 (different principal).\n"
        f"Secure outcome: {secure}\n"
        f"Vulnerable outcome: {vulnerable}"
    )
    return {
        "instruction": "Analyze this artifact for missing authorization invariants and provide deterministic verification.",
        "context": context,
        "target": target,
        "tag": "absence_logic",
        "id": f"absence-{idx:04d}",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate absence-logic dataset")
    parser.add_argument(
        "--output",
        default=str(TRAINING_DIR / "sft" / "absence_logic.jsonl"),
        help="Output JSONL file",
    )
    args = parser.parse_args()

    seeds = [
        ("/api/v1/accounts/{accountId}", "owner/tenant check on accountId", "second principal denied (403/404)", "second principal receives same account payload as authorized principal"),
        ("/api/v2/claims/{claimId}", "claim-to-caller relationship check", "second principal denied or redacted", "second principal reads/modifies foreign claim"),
        ("/css/s/sfsites/aura?r=11&aura.RecordUi.getRecordWithFields=1", "field-level access enforcement on requested fields", "restricted fields stripped/denied", "attacker adds hidden fields and receives values"),
        ("/css/s/sfsites/aura?r=41&aura.RecordUi.executeGraphQL=1", "server-side filter ownership constraint", "foreign filter returns empty/denied", "filter widening returns foreign records"),
        ("/api/v1/orders/bulk", "per-ID ownership filtering in bulk operations", "foreign IDs dropped/denied", "foreign IDs included in result"),
    ]
    rows = [_record(i + 1, *s) for i, s in enumerate(seeds)]
    out = Path(args.output).resolve()
    write_jsonl(out, rows)
    write_json(
        TRAINING_DIR / "absence_logic_manifest.json",
        {"created_at": utc_ts(), "output": str(out), "count": len(rows)},
    )
    print(f"Wrote {out} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

