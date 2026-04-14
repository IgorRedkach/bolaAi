# Expected Response

## System
- **Domain:** Smart Home / Building Automation
- **System:** NeoBuild BAS Platform
- **Example ID:** GQL-0193

## Priority Findings

### Finding 1: Smart Home BAS — Schema/Relationship Over-Exposure via updateResource Enables Cross-Tenant Device Data Access (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration / Schema/Relationship Over-Exposure

**Summary:**
Per §4.0 (RISK-GQL-193): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 6.1 — schema/relationship over-exposure): the GraphQL schema exposes internal relationship fields (e.g., `ownerId`, `tenantId`, `sensitiveField`) that should not be accessible cross-tenant, and the `updateResource` mutation accepts `ownerId` in its input, over-exposing the schema's relationship model. An attacker from `tenant-1531` submitted `updateResource(id: "R-2193", input: {status: "approved", ownerId: "attacker-15311211"})` and received device data belonging to `tenant-1211`, including `CONFIDENTIAL-15311211`. In Smart Home / Building Automation, cross-tenant access to device configurations and automation rules enables physical access bypass and safety system interference.

**Evidence from HAR:**
- Request: `POST https://api.neobuild-bas-platfor.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-1531`
- Mutation: `updateResource(id: "R-2193", input: {status: "approved", ownerId: "attacker-15311211"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-1211"`, `ownerId: "other-user-15311211"`, `sensitiveField: "CONFIDENTIAL-15311211"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-15311211`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-193 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 6.1 | Schema/relationship over-exposure via mutation input |
| HAR mutation | input.ownerId | attacker-15311211 (client-injected) |
| HAR response | tenantId | tenant-1211 returned to tenant-1531 |
| HAR response | sensitiveField | CONFIDENTIAL-15311211 |
| HAR header | x-request-id | req-15311211 |

## Steps to Reproduce

### Step 1 — updateResource schema over-exposure cross-tenant (HAR)
```bash
curl -s -X POST https://api.neobuild-bas-platfor.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1531" \
  -d '{"query": "mutation { updateResource(id: \"R-2193\", input: {status: \"approved\", ownerId: \"attacker-15311211\"}) { resourceId status } }"}'
```
**Vulnerable:** Returns `tenant-1211` smart home device data including `CONFIDENTIAL-15311211`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Remove `ownerId` and `tenantId` from all mutation input types in the GraphQL schema.
3. Disable introspection in production to prevent schema over-exposure.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
