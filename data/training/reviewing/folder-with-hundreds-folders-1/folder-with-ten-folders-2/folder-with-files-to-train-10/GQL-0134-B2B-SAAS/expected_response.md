# Expected Response

## System
- Domain: B2B SaaS / CRM
- System: PipelinePro Sales API
- Example ID: GQL-0134

## Priority Findings

### Finding 1: B2B CRM — Related Project Resource Exposed Cross-Tenant (Pattern 1.2)
**Severity:** High
**Category:** BOLA / Related or Linked Resources

**Summary:**
Per §5.0 (Pattern 1.2 — related or linked resources): The `getProject` resolver fetches by `projectId` without enforcing tenancy, enabling cross-tenant access to linked CRM pipeline data. An attacker from `tenant-daf2` queried `getProject(id: "P-2134")` and received sales project data belonging to `tenant-7e01`, including `CONFIDENTIAL-daf27e01`. In B2B SaaS / CRM, this exposes confidential deal values, pipeline stages, competitor intelligence, and customer relationship data.

**Evidence from HAR:**
- Request: `POST https://api.pipelinepro-sales-ap.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-daf2`
- Query: `getProject(id: "P-2134") { projectId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-7e01"`, `ownerId: "other-user-daf27e01"`, `sensitiveField: "CONFIDENTIAL-daf27e01"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-daf27e01`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.2 | getProject, no tenancy, linked resources |
| HAR request | x-tenant-id | Attacker tenant-daf2 |
| HAR response | tenantId | Cross-tenant tenant-7e01 CRM data |
| HAR response | sensitiveField | CONFIDENTIAL-daf27e01 |

## Steps to Reproduce

### Step 1 — getProject cross-tenant (HAR)
```bash
curl -s -X POST https://api.pipelinepro-sales-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-daf2" \
  -d '{"query": "query { getProject(id: \"P-2134\") { projectId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-7e01` CRM data returned. **Secure:** FORBIDDEN.

## Remediation
1. `getProject` resolver: `WHERE project_id=$id AND tenant_id=$jwt.tenantId`.
2. Apply tenancy guards on all linked/related resource resolvers (contacts, deals, activities).
3. Redis cache key: `project:{tenantId}:{projectId}`.
