# Expected Response

## System
- Domain: Retail / Loyalty Programme
- System: RewardCore Loyalty API
- Example ID: GQL-0123

## Priority Findings

### Finding 1: Retail Loyalty — Over-Broad listResources Endpoint Exposes Cross-Tenant Loyalty Data (Pattern 3.3)
**Severity:** High
**Category:** Insecure Design / Semantic Ambiguity / Over-Broad Endpoints

**Summary:**
Per §4.0 RISK-GQL-123 and §5.0 (Pattern 3.3 — semantic ambiguity / over-broad endpoints): The `listResources` resolver is semantically over-broad, accepting a client-supplied `tenantId` filter rather than scoping results to the caller's JWT tenant. An attacker from `tenant-69ae` passed `tenantId: "tenant-e99d"` and received loyalty programme data belonging to `tenant-e99d`, including `CONFIDENTIAL-69aee99d`. In Retail / Loyalty, this exposes customer loyalty points balances, redemption history, and programme membership data.

**Evidence from HAR:**
- Request: `POST https://api.rewardcore-loyalty-a.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-69ae`
- Query: `listResources(tenantId: "tenant-e99d") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-e99d"`, `ownerId: "other-user-69aee99d"`, `sensitiveField: "CONFIDENTIAL-69aee99d"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-69aee99d`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-123 | getResource resolver, no ownership |
| context.txt §5.0 | Pattern 3.3 | Over-broad listResources endpoint |
| HAR request | tenantId argument | tenant-e99d (victim, client-supplied) |
| HAR response | sensitiveField | CONFIDENTIAL-69aee99d |

## Steps to Reproduce

### Step 1 — listResources with cross-tenant filter (HAR)
```bash
curl -s -X POST https://api.rewardcore-loyalty-a.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-69ae" \
  -d '{"query": "query { listResources(tenantId: \"tenant-e99d\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-e99d` loyalty data returned. **Secure:** Only `tenant-69ae` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg from `listResources` schema; derive from `$jwt.tenantId` only.
2. Resolver filter: `WHERE tenant_id = $jwt.tenantId`.
3. Narrow the endpoint scope — split into domain-specific resolvers.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
