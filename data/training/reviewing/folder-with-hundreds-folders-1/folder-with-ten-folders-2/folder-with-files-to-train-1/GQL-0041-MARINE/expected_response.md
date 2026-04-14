# Expected Response

## System
- Domain: Marine / Port Logistics
- System: HarborFlow Port API
- Example ID: GQL-0041

## Priority Findings

### Finding 1: Cross-Tenant Write + ownerId Hijack via updateShipment — Single-Endpoint Mutation Accessible Without Per-Operation Auth (Pattern 9.1)
**Severity:** Critical
**Category:** BOLA / Platform / Insecure Design

**Summary:**
The GraphQL API uses a single endpoint (`POST /graphql`) for all operations including sensitive write mutations. Per §5.0, per-operation authorization is missing for write operations. An attacker from `tenant-3237` called `updateShipment(id: "S-2041", ...)` targeting a shipment belonging to `tenant-ad04`, injecting `status: "approved"` and `ownerId: "attacker-3237ad04"` through the mutation input. The response `200 OK` confirms the cross-tenant write succeeded and ownership was hijacked. The single `/graphql` endpoint provides no structural barrier between read and write operations — a WAF or API gateway cannot distinguish them by URL alone.

**Evidence from HAR:**
- Request: `POST https://api.harborflow-port-api.example.com/graphql` (2026-04-13T16:22:34Z, 153 ms)
- JWT `x-tenant-id`: `tenant-3237` — attacker's identity
- Mutation payload: `updateShipment(id: "S-2041", input: {status: "approved", ownerId: "attacker-3237ad04"})` — cross-tenant write with injected ownerId
- Response HTTP status: `200 OK` — mutation succeeded, no authorization error
- Response `tenantId`: `tenant-ad04` — victim's shipment record was modified
- Response `ownerId`: `other-user-3237ad04`
- Response `sensitiveField`: `CONFIDENTIAL-3237ad04` — logistics data disclosed
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-3237ad04`

**Root Cause (§4.0 RISK-GQL-041 + §5.0):** The `updateShipment` resolver fetches and writes by `shipmentId` only without asserting `WHERE tenant_id = $jwt.tenantId`. §5.0: "The GraphQL single-endpoint pattern means all operations (including sensitive mutations) are accessible at one URL. Per-operation authorization is missing for write operations." Additionally, `ShipmentInput` accepts `ownerId` as a mass-assignable field.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-041 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 9.1 | "per-operation authorization is missing for write operations" |
| HAR entry | request.postData | `updateShipment(id: "S-2041", input: {status: "approved", ownerId: "attacker-3237ad04"})` |
| HAR entry | response.content | `tenantId: "tenant-ad04"`, `200 OK` — cross-tenant write + ownership hijack confirmed |

---

### Finding 2: Cross-Tenant Bulk Enumeration via bulkShipmentLookup (Pattern 1.9)
**Severity:** High
**Category:** BOLA / Mass Enumeration

**Root Cause (§4.0):** "The `bulkShipmentLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

---

## Steps to Reproduce

### Step 1 — Confirm attacker baseline (own tenant shipment)
```bash
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3237" \
  -d '{"query": "mutation { updateShipment(id: \"S-3237-001\", input: {status: \"pending\"}) { shipmentId status tenantId } }"}'
```
**Expected:** Updates own-tenant shipment only; `tenantId: "tenant-3237"`.

### Step 2 — Cross-tenant write + ownerId injection (HAR attack)
```bash
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3237" \
  -d '{"query": "mutation { updateShipment(id: \"S-2041\", input: {status: \"approved\", ownerId: \"attacker-3237ad04\"}) { shipmentId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, shipment `S-2041` (belonging to `tenant-ad04`) updated to `status: "approved"`, `ownerId` hijacked to `attacker-3237ad04` — cross-tenant write + ownership takeover confirmed.
**Secure outcome:** HTTP 403 or `{"errors": [{"message": "Forbidden"}], "data": {"updateShipment": null}}`.

### Step 3 — Bulk cross-tenant shipment enumeration
```bash
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-3237" \
  -d '{"query": "mutation { bulkShipmentLookup(ids: [\"S-2041\", \"S-ad04-002\"]) { shipmentId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns shipment records from `tenant-ad04`.
**Secure outcome:** Only own-tenant records returned; cross-tenant IDs yield null or FORBIDDEN.

## Secure Outcome Verification
For **Step 2**, a correctly patched implementation MUST return:
```json
{
  "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }],
  "data": { "updateShipment": null }
}
```

## Remediation
1. **Resolver-level tenant guard on updateShipment:** Before applying the update, verify `WHERE shipment_id = $id AND tenant_id = $jwt.tenantId`. Reject with FORBIDDEN if the shipment belongs to a different tenant.
2. **Strip ownerId from ShipmentInput:** `ownerId` must NOT be accepted as a client-supplied field — derive ownership from the JWT's `sub` only.
3. **Per-operation authorization middleware:** For the single `/graphql` endpoint, apply GraphQL middleware that distinguishes mutations from queries and enforces stricter authorization for write operations (Pattern 9.1 remediation).
4. **Per-ID ownership filter in bulkShipmentLookup:** Post-fetch, reject any result whose `tenant_id` ≠ JWT's `tenantId`.
5. **Redis cache key includes tenantId:** §2.0 caches by `shipmentId` only — change to `shipmentId:tenantId`.
6. **Automated regression tests:** Assert `tenant-3237` calling `updateShipment(id: "S-2041", ...)` on a `tenant-ad04` shipment receives FORBIDDEN.
