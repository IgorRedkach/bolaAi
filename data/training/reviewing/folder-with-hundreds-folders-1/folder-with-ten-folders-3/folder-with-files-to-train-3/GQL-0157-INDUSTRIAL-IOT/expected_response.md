# Expected Response

## System
- Domain: Industrial IoT / Manufacturing
- System: ManuControl Robotics Fleet
- Example ID: GQL-0157

## Priority Findings

### Finding 1: Industrial IoT — Bulk List Endpoint Exposes Cross-Tenant Robotics Data (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA / Bulk or List Endpoints

**Summary:**
Per §5.0 (Pattern 1.3 — bulk or list endpoints): The `listResources` resolver accepts a client-supplied `tenantId` filter without validation, enabling bulk cross-tenant data access. An attacker from `tenant-227f` passed `tenantId: "tenant-6031"` and received manufacturing robotics fleet data belonging to `tenant-6031`, including `CONFIDENTIAL-227f6031`. In Industrial IoT, this exposes robot control parameters, manufacturing line configurations, and production metrics.

**Evidence from HAR:**
- Request: `POST https://api.manucontrol-robotics.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-227f`
- Query: `listResources(tenantId: "tenant-6031") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-6031"`, `ownerId: "other-user-227f6031"`, `sensitiveField: "CONFIDENTIAL-227f6031"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-227f6031`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.3 | Bulk list endpoint, client tenantId |
| HAR request | tenantId argument | tenant-6031 (victim, client-supplied) |
| HAR response | tenantId | tenant-6031 robotics data returned |
| HAR response | sensitiveField | CONFIDENTIAL-227f6031 |

## Steps to Reproduce

### Step 1 — listResources with cross-tenant filter (HAR)
```bash
curl -s -X POST https://api.manucontrol-robotics.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-227f" \
  -d '{"query": "query { listResources(tenantId: \"tenant-6031\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-6031` robotics data returned. **Secure:** Only `tenant-227f` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg from `listResources`; derive from `$jwt.tenantId` only.
2. Resolver: `WHERE tenant_id = $jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
