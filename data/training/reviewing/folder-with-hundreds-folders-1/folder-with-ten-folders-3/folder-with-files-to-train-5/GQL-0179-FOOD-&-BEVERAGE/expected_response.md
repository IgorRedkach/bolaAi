# Expected Response

## System
- **Domain:** Food & Beverage / Supply Chain
- **System:** TraceOrigin Supply API
- **Example ID:** GQL-0179

## Priority Findings

### Finding 1: Food & Beverage Supply Chain — BOLA via Bulk/List Endpoint Exposes Cross-Tenant Traceability Data (Pattern 1.3)
**Severity:** High
**Category:** BOLA / Bulk or List Endpoints

**Summary:**
Per §4.0 (RISK-GQL-179): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.3 — bulk or list endpoints): the list/bulk endpoint returns supply chain records across tenant boundaries when a caller-controlled `tenantId` filter is accepted or ignored. An attacker from `tenant-3d4e` queried `getResource(id: "R-2179")` and received the supply chain traceability record belonging to `tenant-3a41`, including `CONFIDENTIAL-3d4e3a41`. In Food & Beverage supply chain, exposure of origin traceability records, supplier contracts, and recall workflows to competitors constitutes a material business and regulatory risk.

**Evidence from HAR:**
- Request: `POST https://api.traceorigin-supply-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-3d4e`
- Query: `getResource(id: "R-2179") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-3a41"`, `ownerId: "other-user-3d4e3a41"`, `sensitiveField: "CONFIDENTIAL-3d4e3a41"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-3d4e3a41`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-179 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.3 | Bulk/list endpoint returns cross-tenant supply records |
| HAR query | id: "R-2179" | Cross-tenant supply chain record lookup |
| HAR response | tenantId | tenant-3a41 returned to tenant-3d4e |
| HAR response | sensitiveField | CONFIDENTIAL-3d4e3a41 |
| HAR header | x-request-id | req-3d4e3a41 |

## Steps to Reproduce

### Step 1 — getResource bulk/list BOLA cross-tenant access (HAR)
```bash
curl -s -X POST https://api.traceorigin-supply-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3d4e" \
  -d '{"query": "query { getResource(id: \"R-2179\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-3a41` supply chain record including `CONFIDENTIAL-3d4e3a41`. **Secure:** FORBIDDEN — only `tenant-3d4e` records accessible.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. List/bulk endpoints must enforce `tenant_id = $jwt.tenantId` filter server-side, never trust caller-supplied `tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
