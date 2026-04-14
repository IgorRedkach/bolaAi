# Expected Response

## System
- Domain: SaaS / Project Management
- System: TaskFlow Collaboration API
- Example ID: GQL-0160

## Priority Findings

### Finding 1: SaaS Project Management — Nested Project Resource Bypasses Parent Authorization (Pattern 1.7)
**Severity:** High
**Category:** BOLA / Nested Resources Without Parent Authorization

**Summary:**
Per §5.0 (Pattern 1.7 — nested resources without parent authorization): The `getProject` resolver fetches nested project resources without verifying the parent resource's tenancy. An attacker from `tenant-0621` queried `getProject(id: "P-2160")` and received project collaboration data belonging to `tenant-5665`, including `CONFIDENTIAL-06215665`. In SaaS / Project Management, this exposes project roadmaps, task assignments, and inter-team communications.

**Evidence from HAR:**
- Request: `POST https://api.taskflow-collaborati.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-0621`
- Query: `getProject(id: "P-2160") { projectId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-5665"`, `ownerId: "other-user-06215665"`, `sensitiveField: "CONFIDENTIAL-06215665"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-06215665`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.7 | Nested resource, parent auth bypass |
| HAR request | x-tenant-id | Attacker tenant-0621 |
| HAR response | tenantId | Cross-tenant project data tenant-5665 |
| HAR response | sensitiveField | CONFIDENTIAL-06215665 |

## Steps to Reproduce

### Step 1 — getProject nested resource bypass (HAR)
```bash
curl -s -X POST https://api.taskflow-collaborati.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0621" \
  -d '{"query": "query { getProject(id: \"P-2160\") { projectId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-5665` project data returned. **Secure:** FORBIDDEN.

## Remediation
1. Validate parent tenancy before resolving nested children: `WHERE project_id=$id AND tenant_id=$jwt.tenantId`.
2. Apply resolver middleware to all nested resource types.
3. Redis cache key: `project:{tenantId}:{projectId}`.
