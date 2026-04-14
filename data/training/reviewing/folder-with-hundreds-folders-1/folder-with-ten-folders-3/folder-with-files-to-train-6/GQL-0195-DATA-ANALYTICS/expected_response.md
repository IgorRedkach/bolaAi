# Expected Response

## System
- **Domain:** Data Analytics / Business Intelligence
- **System:** InsightGraph Analytics API
- **Example ID:** GQL-0195

## Priority Findings

### Finding 1: Analytics Platform — GraphQL Single Endpoint Vulnerability via getResource Exposes Cross-Tenant Analytics Data (Pattern 9.1)
**Severity:** High
**Category:** GraphQL Platform / Single Endpoint Vulnerabilities

**Summary:**
Per §4.0 (RISK-GQL-195): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 9.1 — GraphQL single endpoint vulnerabilities): the single `/graphql` endpoint aggregates all operations without per-operation tenant isolation, allowing any authenticated user to query any resource ID regardless of tenant ownership. An attacker from `tenant-3333` queried `getResource(id: "R-2195")` and received analytics data belonging to `tenant-06eb`, including `CONFIDENTIAL-333306eb`. In Data Analytics / Business Intelligence, cross-tenant access to dashboards, query results, and data pipelines constitutes a competitive intelligence and data sovereignty breach.

**Evidence from HAR:**
- Request: `POST https://api.insightgraph-analyti.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-3333`
- Query: `getResource(id: "R-2195") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-06eb"`, `ownerId: "other-user-333306eb"`, `sensitiveField: "CONFIDENTIAL-333306eb"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-333306eb`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-195 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 9.1 | GraphQL single endpoint — no per-operation tenant isolation |
| HAR query | id: "R-2195" | Cross-tenant analytics data lookup |
| HAR response | tenantId | tenant-06eb returned to tenant-3333 |
| HAR response | sensitiveField | CONFIDENTIAL-333306eb |
| HAR header | x-request-id | req-333306eb |

## Steps to Reproduce

### Step 1 — getResource GraphQL single endpoint cross-tenant (HAR)
```bash
curl -s -X POST https://api.insightgraph-analyti.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3333" \
  -d '{"query": "query { getResource(id: \"R-2195\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-06eb` analytics record including `CONFIDENTIAL-333306eb`. **Secure:** FORBIDDEN — only `tenant-3333` resources accessible.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Apply tenant context middleware at the GraphQL gateway layer for every incoming operation.
3. Disable introspection in production.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
