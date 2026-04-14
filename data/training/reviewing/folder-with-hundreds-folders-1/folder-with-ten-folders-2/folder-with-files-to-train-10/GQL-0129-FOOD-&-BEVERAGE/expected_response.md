# Expected Response

## System
- Domain: Food & Beverage / FMCG
- System: TraceOrigin Supply API
- Example ID: GQL-0129

## Priority Findings

### Finding 1: Food & Beverage Supply Chain — Single GraphQL Endpoint Exposes Cross-Tenant Traceability Data (Pattern 9.1)
**Severity:** Critical
**Category:** GraphQL Platform / Single Endpoint Vulnerability

**Summary:**
Per §5.0 (Pattern 9.1 — GraphQL single endpoint vulnerabilities): The unified GraphQL endpoint does not enforce per-operation tenant isolation, enabling cross-tenant access via the `getResource` resolver. An attacker from `tenant-edc4` queried `getResource(id: "R-2129")` and received food supply traceability data belonging to `tenant-00d9`, including `CONFIDENTIAL-edc400d9`. In Food & Beverage / FMCG, this exposes origin-to-shelf traceability records, supplier identities, and quality control data.

**Evidence from HAR:**
- Request: `POST https://api.traceorigin-supply-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-edc4`
- Query: `getResource(id: "R-2129") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-00d9"`, `ownerId: "other-user-edc400d9"`, `sensitiveField: "CONFIDENTIAL-edc400d9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-edc400d9`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 9.1 | Single endpoint, no per-op tenant guard |
| HAR request | x-tenant-id | Attacker tenant-edc4 |
| HAR response | tenantId | Cross-tenant tenant-00d9 data returned |
| HAR response | sensitiveField | CONFIDENTIAL-edc400d9 |

## Steps to Reproduce

### Step 1 — getResource cross-tenant via single endpoint (HAR)
```bash
curl -s -X POST https://api.traceorigin-supply-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-edc4" \
  -d '{"query": "query { getResource(id: \"R-2129\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-00d9` supply data returned. **Secure:** FORBIDDEN.

## Remediation
1. Per-operation tenant guard on the single endpoint.
2. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Disable GraphQL introspection in production.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
