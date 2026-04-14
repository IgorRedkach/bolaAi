# Expected Response

## System
- **Domain:** SaaS / Collaboration Platform
- **System:** TaskFlow Collaboration API
- **Example ID:** GQL-0210

## Priority Findings

### Finding 1: SaaS Collaboration — Insecure Design via Client-Assumed Authority in updateProject Exposes Cross-Tenant Project Data (Pattern 3.1)
**Severity:** High
**Category:** Insecure Design / Client-Assumed Authority

**Summary:**
Per §4.0 (RISK-GQL-210): The `getProject` resolver fetches by `projectId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 3.1 — client-assumed authority): the `updateProject` mutation trusts client-supplied `ownerId` as an authority claim, rather than deriving it from the JWT. An attacker from `tenant-c34f` submitted `updateProject(id: "P-2210", input: {status: "approved", ownerId: "attacker-c34fb8f9"})` against a project belonging to `tenant-b8f9`, receiving `CONFIDENTIAL-c34fb8f9`. In SaaS / Collaboration, unauthorized access to project roadmaps, team communications, and business logic constitutes an IP theft and competitive intelligence breach.

**Evidence from HAR:**
- Request: `POST https://api.taskflow-collaborati.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-c34f`
- Mutation: `updateProject(id: "P-2210", input: {status: "approved", ownerId: "attacker-c34fb8f9"}) { projectId status }`
- Response `200 OK`: `tenantId: "tenant-b8f9"`, `ownerId: "other-user-c34fb8f9"`, `sensitiveField: "CONFIDENTIAL-c34fb8f9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c34fb8f9`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-210 | getProject resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 3.1 | Client-assumed authority — client-supplied ownerId accepted |
| HAR mutation | input.ownerId | attacker-c34fb8f9 (client-injected authority claim) |
| HAR response | tenantId | tenant-b8f9 returned to tenant-c34f |
| HAR response | sensitiveField | CONFIDENTIAL-c34fb8f9 |
| HAR header | x-request-id | req-c34fb8f9 |

## Steps to Reproduce

### Step 1 — updateProject client-assumed authority insecure design (HAR)
```bash
curl -s -X POST https://api.taskflow-collaborati.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c34f" \
  -d '{"query": "mutation { updateProject(id: \"P-2210\", input: {status: \"approved\", ownerId: \"attacker-c34fb8f9\"}) { projectId status } }"}'
```
**Vulnerable:** `tenant-b8f9` project mutated, returns `CONFIDENTIAL-c34fb8f9`. **Secure:** FORBIDDEN — authority derived from JWT only.

## Remediation
1. Resolver: `WHERE project_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ProjectInput`; derive `ownerId` and `tenantId` from JWT exclusively.
3. Redis cache key: `project:{tenantId}:{projectId}`.
