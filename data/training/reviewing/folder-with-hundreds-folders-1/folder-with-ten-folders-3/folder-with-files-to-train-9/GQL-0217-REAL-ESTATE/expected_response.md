# Expected Response

## System
- **Domain:** Real Estate / Property Marketplace
- **System:** EstateFlow Property API
- **Example ID:** GQL-0217

## Priority Findings

### Finding 1: Real Estate — GraphQL Single Endpoint Vulnerability via listResources Exposes Cross-Tenant Property Data (Pattern 9.1)
**Severity:** High
**Category:** GraphQL Platform / Single Endpoint Vulnerabilities

**Summary:**
Per §4.0 (RISK-GQL-217): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 9.1 — GraphQL single endpoint vulnerabilities): the single `/graphql` endpoint has no per-operation tenant enforcement middleware, allowing any authenticated user to enumerate property listings and records of other tenants by supplying their `tenantId`. An attacker from `tenant-c805` queried `listResources(tenantId: "tenant-e10d")` and received property data belonging to `tenant-e10d`, including `CONFIDENTIAL-c805e10d`. In Real Estate / Property Marketplace, cross-tenant access to property portfolios, valuations, and client data represents a business and privacy breach.

**Evidence from HAR:**
- Request: `POST https://api.estateflow-property-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-c805`
- Query: `listResources(tenantId: "tenant-e10d") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-e10d"`, `ownerId: "other-user-c805e10d"`, `sensitiveField: "CONFIDENTIAL-c805e10d"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c805e10d`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-217 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 9.1 | GraphQL single endpoint — no per-operation tenant isolation |
| HAR query | tenantId: "tenant-e10d" | Injected cross-tenant property filter |
| HAR response | tenantId | tenant-e10d returned to tenant-c805 |
| HAR response | sensitiveField | CONFIDENTIAL-c805e10d |
| HAR header | x-request-id | req-c805e10d |

## Steps to Reproduce

### Step 1 — listResources GraphQL single endpoint cross-tenant real estate (HAR)
```bash
curl -s -X POST https://api.estateflow-property-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c805" \
  -d '{"query": "query { listResources(tenantId: \"tenant-e10d\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-e10d` property records including `CONFIDENTIAL-c805e10d`. **Secure:** FORBIDDEN — `tenantId` from JWT; only `tenant-c805` properties returned.

## Remediation
1. Ignore caller-supplied `tenantId`; apply tenant context middleware at GraphQL gateway for every operation.
2. Resolver: `WHERE tenant_id = $jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
