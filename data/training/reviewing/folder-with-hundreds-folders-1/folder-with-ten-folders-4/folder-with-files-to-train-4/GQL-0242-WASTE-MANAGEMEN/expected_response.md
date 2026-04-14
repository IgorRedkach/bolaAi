# Security Analysis Report
**System:** CleanRoute IoT Platform (Waste Management / Smart Bins)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0242 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User / Pattern 10.5 | Draft/non-published resource access — cross-tenant IoT waste management route data accessed via `bulkResourceLookup` |

---

## Finding 1 — Draft/Non-Published Resource Access via Bulk Lookup (CRITICAL)

### Summary
The `bulkResourceLookup` mutation on CleanRoute IoT Platform (`api.cleanroute-iot-platf.example.com`) accepts an arbitrary list of resource IDs with no per-ID ownership validation. Per §5.0 Pattern 10.5, this exposes draft/non-published resources: IoT route configurations, sensor calibration data, and route planning documents in `draft` or `pending` state belonging to `tenant-a96a` are accessible to an attacker from `tenant-b60d` — data that has not yet been published/active but is already stored and queryable. Sequential resource IDs `["R-2242", "R-1242", "R-3242"]` enable systematic enumeration.

**Pattern:** 10.5 — Draft/non-published resource access (Single-User)
**Affected resolver:** `bulkResourceLookup(ids: [ID!]!): [Resource!]`
**Affected endpoint:** `POST https://api.cleanroute-iot-platf.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-b60d`):**
```
POST https://api.cleanroute-iot-platf.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-b60d

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2242\", \"R-1242\", \"R-3242\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-a96a",
      "ownerId": "other-user-b60da96a",
      "data": {"sensitiveField": "CONFIDENTIAL-b60da96a", "internalNotes": "Internal data exposed"}
    }
  }
}
```

**x-request-id:** `req-b60da96a`

Waste management route data includes collection schedules, IoT sensor configs, bin fill-level data, and route optimization parameters — cross-tenant access enables competitor intelligence gathering and route disruption.

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-242 | Resolver gap | No per-ID tenancy check | Root cause |
| §5.0 Pattern 10.5 | Vulnerability | Draft/non-published resource accessible | Classification |
| HAR request | `ids` | `["R-2242","R-1242","R-3242"]` | Sequential IDs from victim tenant |
| HAR response | `tenantId` | `tenant-a96a` | Victim confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-b60da96a` | IoT route data |
| HAR headers | `x-request-id` | `req-b60da96a` | Correlation ID |

### Steps to Reproduce
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.cleanroute-iot-platf.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-b60d" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { bulkResourceLookup(ids: [\"R-2242\",\"R-1242\",\"R-3242\"]) { resourceId tenantId data { sensitiveField } } }"}' \
  | jq '.data.bulkResourceLookup'
# VULNERABLE: tenant-a96a data with CONFIDENTIAL-b60da96a
```

### Remediation
1. Per-ID tenancy filter in `bulkResourceLookup`: `return resources.filter(r => r.tenantId === context.auth.tenantId)`
2. Draft resources must have the same tenancy enforcement as published resources — status does not affect authorization.
3. Non-guessable IDs: replace sequential `R-XXXX` with UUIDs.
4. Fix Redis cache key with `tenantId`.
5. PostgreSQL RLS enforcement as defence-in-depth.
