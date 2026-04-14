# Expected Response

## System
- Domain: Railway / SCADA
- System: RailCore Operations API
- Example ID: GQL-0138

## Priority Findings

### Finding 1: Railway SCADA — Nested Resource Parent Auth Bypass Exposes Cross-Tenant Operations Data (Pattern 1.7)
**Severity:** Critical
**Category:** BOLA / Nested Resources Without Parent Authorization

**Summary:**
Per §5.0 (Pattern 1.7 — nested resources without parent authorization): The `listResources` resolver accepts a client-supplied `tenantId` parameter without verifying the parent resource's tenancy. An attacker from `tenant-4648` passed `tenantId: "tenant-105c"` and received railway SCADA operations data belonging to `tenant-105c`, including `CONFIDENTIAL-4648105c`. In Railway / SCADA, unauthorized access to operations data exposes signal controls, track scheduling, and infrastructure states that are safety-critical.

**Evidence from HAR:**
- Request: `POST https://api.railcore-operations-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-4648`
- Query: `listResources(tenantId: "tenant-105c") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-105c"`, `ownerId: "other-user-4648105c"`, `sensitiveField: "CONFIDENTIAL-4648105c"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-4648105c`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.7 | Nested resources, parent auth bypass |
| HAR request | tenantId argument | tenant-105c (victim, client-supplied) |
| HAR response | tenantId | tenant-105c SCADA data returned |
| HAR response | sensitiveField | CONFIDENTIAL-4648105c |

## Steps to Reproduce

### Step 1 — listResources bypassing parent auth (HAR)
```bash
curl -s -X POST https://api.railcore-operations-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4648" \
  -d '{"query": "query { listResources(tenantId: \"tenant-105c\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-105c` SCADA data returned. **Secure:** Only `tenant-4648` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg; derive from `$jwt.tenantId` only.
2. Validate parent resource tenancy before returning nested children.
3. Resolver: `WHERE tenant_id = $jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
