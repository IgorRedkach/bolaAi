# Expected Response

## System
- **Domain:** Aviation / Flight Operations
- **System:** AeroOps Flight Management
- **Example ID:** GQL-0187

## Priority Findings

### Finding 1: Aviation — BAC Metadata Side-Channel via updateResource Exposes Cross-Tenant Flight Data (Pattern 2.2)
**Severity:** High
**Category:** Broken Access Control / Metadata/Attribute Side-Channel

**Summary:**
Per §4.0 (RISK-GQL-187): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 2.2 — metadata/attribute side-channel): the `updateResource` mutation returns metadata attributes (e.g., `ownerId`, `status`, `sensitiveField`) in its response that leak cross-tenant ownership data through an attribute side-channel. An attacker from `tenant-84bf` submitted `updateResource(id: "R-2187", input: {status: "approved", ownerId: "attacker-84bf62b1"})` and received a response including flight record data belonging to `tenant-62b1`, including `CONFIDENTIAL-84bf62b1`. In Aviation / Flight Operations, cross-tenant access to flight schedules, operational logs, and crew data constitutes an aviation security and safety incident.

**Evidence from HAR:**
- Request: `POST https://api.aeroops-flight-manag.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-84bf`
- Mutation: `updateResource(id: "R-2187", input: {status: "approved", ownerId: "attacker-84bf62b1"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-62b1"`, `ownerId: "other-user-84bf62b1"`, `sensitiveField: "CONFIDENTIAL-84bf62b1"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-84bf62b1`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-187 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 2.2 | Metadata/attribute side-channel via mutation response |
| HAR mutation | input.ownerId | attacker-84bf62b1 (client-injected) |
| HAR response | tenantId | tenant-62b1 leaked to tenant-84bf |
| HAR response | sensitiveField | CONFIDENTIAL-84bf62b1 |
| HAR header | x-request-id | req-84bf62b1 |

## Steps to Reproduce

### Step 1 — updateResource metadata side-channel BAC (HAR)
```bash
curl -s -X POST https://api.aeroops-flight-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-84bf" \
  -d '{"query": "mutation { updateResource(id: \"R-2187\", input: {status: \"approved\", ownerId: \"attacker-84bf62b1\"}) { resourceId status } }"}'
```
**Vulnerable:** Returns `tenant-62b1` flight record metadata including `CONFIDENTIAL-84bf62b1`. **Secure:** FORBIDDEN — mutation rejected if `tenant_id != jwt.tenantId`.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`; derive from JWT.
3. Mutation response must not return cross-tenant metadata attributes.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
