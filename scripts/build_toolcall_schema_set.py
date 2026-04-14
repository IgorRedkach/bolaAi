#!/usr/bin/env python3
"""Generate strict payload-shape training tasks for tool usage."""

from __future__ import annotations

import argparse
from pathlib import Path

from training_pipeline_common import TRAINING_DIR, utc_ts, write_json, write_jsonl


def _rest_task() -> dict:
    return {
        "instruction": "Generate two grounded verification requests for this REST endpoint.",
        "context": "Endpoint: GET /api/v2/accounts/{accountId}. Use same object id for AUTH_TOKEN_1 and AUTH_TOKEN_2.",
        "target": (
            "curl -X GET \"https://api.example.com/api/v2/accounts/acc-demo-01\" -H \"Authorization: Bearer AUTH_TOKEN_1\"\n"
            "curl -X GET \"https://api.example.com/api/v2/accounts/acc-demo-01\" -H \"Authorization: Bearer AUTH_TOKEN_2\""
        ),
        "schema_tag": "rest_curl_pair",
    }


def _graphql_task() -> dict:
    return {
        "instruction": "Generate a strict GraphQL verification request pair without inventing fields.",
        "context": "Endpoint: POST /graphql. Operation: query { account(id:\"001demo\"){ id name } }",
        "target": (
            "curl -X POST \"https://api.example.com/graphql\" -H \"Authorization: Bearer AUTH_TOKEN_1\" -H \"Content-Type: application/json\" "
            "-d '{\"query\":\"query { account(id:\\\"001demo\\\"){ id name } }\"}'\n"
            "curl -X POST \"https://api.example.com/graphql\" -H \"Authorization: Bearer AUTH_TOKEN_2\" -H \"Content-Type: application/json\" "
            "-d '{\"query\":\"query { account(id:\\\"001demo\\\"){ id name } }\"}'"
        ),
        "schema_tag": "graphql_curl_pair",
    }


def _aura_task() -> dict:
    return {
        "instruction": "Generate two Aura form-encoded verification requests preserving message/aura fields.",
        "context": (
            "Endpoint: POST /css/s/sfsites/aura?r=11&aura.RecordUi.getRecordWithFields=1\n"
            "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\n"
            "Required form keys: message, aura.context, aura.pageURI, aura.token"
        ),
        "target": (
            "curl -X POST \"https://api.example.com/css/s/sfsites/aura?r=11&aura.RecordUi.getRecordWithFields=1\" "
            "-H \"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\" "
            "--data-urlencode 'message={\"actions\":[{\"params\":{\"recordId\":\"001demo\",\"fields\":[\"Account.Name\"]}}]}' "
            "--data-urlencode 'aura.context={\"mode\":\"PROD\"}' --data-urlencode 'aura.pageURI=/s/account' --data-urlencode 'aura.token=AUTH_TOKEN_1'\n"
            "curl -X POST \"https://api.example.com/css/s/sfsites/aura?r=11&aura.RecordUi.getRecordWithFields=1\" "
            "-H \"Content-Type: application/x-www-form-urlencoded; charset=UTF-8\" "
            "--data-urlencode 'message={\"actions\":[{\"params\":{\"recordId\":\"001demo\",\"fields\":[\"Account.Name\"]}}]}' "
            "--data-urlencode 'aura.context={\"mode\":\"PROD\"}' --data-urlencode 'aura.pageURI=/s/account' --data-urlencode 'aura.token=AUTH_TOKEN_2'"
        ),
        "schema_tag": "aura_form_pair",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate strict tool-call schema dataset")
    parser.add_argument(
        "--output",
        default=str(TRAINING_DIR / "sft" / "toolcall_schema.jsonl"),
        help="Output JSONL file",
    )
    args = parser.parse_args()

    rows = [_rest_task(), _graphql_task(), _aura_task()]
    out = Path(args.output).resolve()
    write_jsonl(out, rows)
    write_json(
        TRAINING_DIR / "toolcall_schema_manifest.json",
        {"created_at": utc_ts(), "output": str(out), "count": len(rows)},
    )
    print(f"Wrote {out} ({len(rows)} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

