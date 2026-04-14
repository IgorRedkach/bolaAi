#!/usr/bin/env python3
"""
Run manual test cases: for each fixture doc, ingest + analyze, then evaluate report
against expected outcomes. Prints PASS/FAIL and any issues. Exit 0 only if all pass.
Usage: BOLA_AI_LIVE_URL=http://localhost:8000 python scripts/run_manual_test_cases.py [--timeout 300]
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))
try:
    from bola_ai import config as _bola_config

    _INGEST_T = float(_bola_config.INGEST_HTTP_TIMEOUT)
except Exception:
    _INGEST_T = 600.0
FIXTURES = REPO_ROOT / "tests" / "fixtures"

# (doc_basename, must_mention_substrings, must_not_contain_patterns, doc_path)
TEST_CASES = [
    (
        "doc_ecommerce_orders.md",
        ["/store/v2/", "order", "invoice"],  # at least one
        ["/api/users/", "/api/tenants", "/api/patients/", "/api/v1/patients"],
        "doc_ecommerce_orders.md",
    ),
    (
        "doc_file_storage.md",
        ["/files/api/", "document", "folder"],
        ["/api/users/", "/api/tenants"],
        "doc_file_storage.md",
    ),
    (
        "doc_support_tickets.md",
        ["/support/", "ticket", "comment"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_support_tickets.md",
    ),
    (
        "sample_project_documentation.md",
        ["/api/", "patient", "order", "prescription", "case"],
        ["/api/users/", "/api/tenants"],  # after redaction these should not appear as raw paths
        "sample_project_documentation.md",
    ),
    (
        "doc_crm_contacts.md",
        ["/v2/contacts/", "/v2/companies/", "contact", "company"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_crm_contacts.md",
    ),
    (
        "doc_banking_api.md",
        ["/banking/v1/", "account", "transfer", "beneficiar"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_banking_api.md",
    ),
    (
        "doc_hr_system.md",
        ["/hr/api/", "employee", "payroll", "review"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_hr_system.md",
    ),
    (
        "doc_gov_grants.md",
        ["/grants/api/v1/", "application", "grant", "disbursement", "agency"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_gov_grants.md",
    ),
    (
        "doc_insurance_claims.md",
        ["/claims/v2/", "claim", "attachment", "insurer", "batch"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_insurance_claims.md",
    ),
    (
        "doc_edu_records.md",
        ["/records/api/", "student", "transcript", "advisor", "campus"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_edu_records.md",
    ),
    # Adversarial: legacy/cross-tenant/role ambiguity
    (
        "doc_adversarial_university.md",
        ["/uni/api/", "student", "advisor", "registrar"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_adversarial_university.md",
    ),
    (
        "doc_adversarial_procurement.md",
        ["/procure/api/", "bid", "contract", "agency"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_adversarial_procurement.md",
    ),
    (
        "doc_adversarial_wallet.md",
        ["/wallet/v3/", "account", "card", "transfer"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_adversarial_wallet.md",
    ),
    # GraphQL / SOQL
    (
        "doc_adversarial_graphql.md",
        ["graphql", "user", "document", "query", "mutation"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_adversarial_graphql.md",
    ),
    (
        "doc_adversarial_salesforce.md",
        ["soql", "salesforce", "account", "case", "opportunity"],
        ["/api/users/", "/api/tenants", "/api/patients/"],
        "doc_adversarial_salesforce.md",
    ),
]


def evaluate_report(doc_name: str, report: str, must_mention: list, must_not: list) -> list[str]:
    issues = []
    r_lower = report.lower()
    # Must mention at least one of the doc-specific strings (evidence we're analyzing this doc)
    if not any(s.lower() in r_lower for s in must_mention):
        issues.append(f"Report does not mention any of {must_mention} (doc-specific context)")
    # Must not contain unredacted hallucinated paths (/api/.../users or .../tenants)
    if re.search(r"/api/[^\s\[\]]*(?:users|tenants)[^\s\[\]]*", report, re.IGNORECASE):
        issues.append("Report contains unredacted /api/.../users or /api/.../tenants path")
    for pattern in must_not:
        if pattern in r_lower:
            issues.append(f"Report contains disallowed path pattern: {pattern}")
            break
    # Verification methodology check — accept single-token ID swap (primary) or two-token (secondary).
    # Single-token: attacker uses own valid token with victim's resource ID.
    # Two-token: comparative test with two different principals (for cross-tenant/cross-role).
    verification_methodology_phrases = [
        # Single-token ID swap methodology (preferred)
        "your own", "your token", "own valid", "swap", "replace", "change the id",
        "victim", "victim id", "victim's", "id swap", "id-swap",
        "own id", "own resource", "own token",
        # Two-token / comparative (acceptable)
        "two different user tokens", "two different users", "two user tokens",
        "token a", "token b", "with token a", "with token b",
        "user a", "user b", "actor a", "actor b",
        "user 1", "user 2", "user_a", "user_b",
        "two users", "two separate", "second user", "another user",
        "different user", "different account", "separate user",
        "attacker", "second account", "another account",
        # Generic verification reminder
        "verification reminder", "baseline", "id probe",
    ]
    if len(report) > 200 and "verification" in r_lower and not any(p.lower() in r_lower for p in verification_methodology_phrases):
        issues.append("Verification section present but no ID-swap or comparison methodology")
    # Duplicate heading
    if "### ###" in report or "#### ###" in report:
        issues.append("Duplicate heading (### ###) in output")
    # Bold-wrapped heading (Issue 8)
    if "**###" in report or "** ###" in report:
        issues.append("Bold-wrapped heading (**### pattern) in output")
    # Verification must use a valid token — testing without auth is not a BOLA test
    if "without a token" in r_lower or "without authentication" in r_lower:
        if "if successful" in r_lower or "bola is confirmed" in r_lower:
            issues.append("Verification suggests testing without token (BOLA requires at least one valid authenticated session)")
    if ("401 unauthorized" in r_lower or "invalid token" in r_lower) and "bola is confirmed" in r_lower:
        issues.append("Verification treats auth failure (401/invalid token) as BOLA confirmation")
    # Rationale should not say "does not require authentication" when doc says auth required
    if "does not require authentication" in r_lower and ("api key" in r_lower or "bearer" in r_lower):
        issues.append("Rationale says no auth but doc describes auth (conflating auth vs ownership)")
    return issues


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--timeout",
        type=float,
        default=300,
        help="POST /analyze timeout only (LLM inference); do not use to extend ingest",
    )
    ap.add_argument(
        "--ingest-timeout",
        type=float,
        default=None,
        help="POST /ingest timeout (embedding/learning); default from BOLA_AI_INGEST_TIMEOUT",
    )
    ap.add_argument("--base-url", default=os.environ.get("BOLA_AI_LIVE_URL", "http://localhost:8000"))
    ap.add_argument("--max-cases", type=int, default=0, help="Limit number of test cases (0=all)")
    args = ap.parse_args()
    base = args.base_url.rstrip("/")
    timeout = args.timeout
    ingest_timeout = float(args.ingest_timeout) if args.ingest_timeout is not None else _INGEST_T
    all_issues = []
    cases_to_run = TEST_CASES if args.max_cases <= 0 else TEST_CASES[: args.max_cases]
    for doc_name, must_mention, must_not, doc_path in cases_to_run:
        path = FIXTURES / doc_path
        if not path.exists():
            print(f"[SKIP] {doc_name}: fixture not found")
            continue
        content = path.read_text()
        print(f"\n=== {doc_name} ===")
        with httpx.Client(timeout=max(60.0, timeout, ingest_timeout)) as client:
            # Reset store so this doc is the only one (avoids mixing with previous test cases)
            try:
                r = client.post(f"{base}/reset", timeout=60.0)
                if r.status_code != 200:
                    print(f"  [WARN] Reset returned {r.status_code} (continuing anyway)")
            except Exception as e:
                print(f"  [WARN] Reset failed: {e} (continuing)")
            # Health
            try:
                r = client.get(f"{base}/health", timeout=30.0)
                if r.status_code != 200:
                    print(f"  [FAIL] API health {r.status_code}")
                    all_issues.append((doc_name, ["API not healthy"]))
                    continue
            except Exception as e:
                print(f"  [FAIL] API unreachable: {e}")
                all_issues.append((doc_name, [str(e)]))
                continue
            # Ingest
            try:
                r = client.post(
                    f"{base}/ingest",
                    files={"content": (None, content)},
                    data={"source": doc_name},
                    timeout=ingest_timeout,
                )
                if r.status_code != 200:
                    print(f"  [FAIL] Ingest {r.status_code}: {r.text[:200]}")
                    all_issues.append((doc_name, [f"Ingest {r.status_code}"]))
                    continue
            except Exception as e:
                print(f"  [FAIL] Ingest error: {e}")
                all_issues.append((doc_name, [str(e)]))
                continue
            # Analyze (retry once on 5xx)
            report = None
            for attempt in range(2):
                try:
                    r = client.post(
                        f"{base}/analyze",
                        json={"query": "Identify BOLA risks and give verification steps for each."},
                        timeout=timeout,
                    )
                    if r.status_code == 200:
                        data = r.json()
                        report = data.get("report", "")
                        break
                    if r.status_code >= 500 and attempt == 0:
                        import time
                        time.sleep(5)
                        continue
                    print(f"  [FAIL] Analyze {r.status_code}: {r.text[:300]}")
                    all_issues.append((doc_name, [f"Analyze {r.status_code}"]))
                    break
                except Exception as e:
                    if attempt == 0:
                        import time
                        time.sleep(5)
                        continue
                    print(f"  [FAIL] Analyze error: {e}")
                    all_issues.append((doc_name, [str(e)]))
                    break
        if report is None:
            continue
        print(f"  Report length: {len(report)}")
        issues = evaluate_report(doc_name, report, must_mention, must_not)
        if issues:
            print(f"  [FAIL] {issues}")
            all_issues.append((doc_name, issues))
        else:
            print(f"  [PASS]")
        # Show tail of report
        print(f"  --- report tail (500 chars) ---")
        print(report[-500:] if len(report) > 500 else report)
        print("  ---")
    if all_issues:
        print("\n=== SUMMARY: FAILED ===")
        for doc_name, issues in all_issues:
            print(f"  {doc_name}: {issues}")
        sys.exit(1)
    print("\n=== SUMMARY: ALL PASSED ===")
    sys.exit(0)


if __name__ == "__main__":
    main()
