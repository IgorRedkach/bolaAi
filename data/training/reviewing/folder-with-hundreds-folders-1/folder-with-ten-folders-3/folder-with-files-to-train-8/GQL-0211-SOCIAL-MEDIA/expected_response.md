# Expected Response

## System
- **Domain:** Social Media / Content Platform
- **System:** Horizon Social Graph API
- **Example ID:** GQL-0211

## Priority Findings

### Finding 1: Social Media — Insecure Design via Semantic Ambiguity in listPosts Exposes Cross-Tenant Private Post Data (Pattern 3.3)
**Severity:** High
**Category:** Insecure Design / Semantic Ambiguity / Over-Broad Endpoints

**Summary:**
Per §4.0 (RISK-GQL-211): The `getPost` resolver fetches by `postId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 3.3 — semantic ambiguity/over-broad endpoints): the `listPosts` endpoint's scope is ambiguous — it does not clearly enforce ownership, allowing a caller to supply another tenant's `tenantId` and receive their private posts. An attacker from `tenant-9c9c` queried `listPosts(tenantId: "tenant-fe91")` and received private post data belonging to `tenant-fe91`, including `CONFIDENTIAL-9c9cfe91`. In Social Media / Content Platforms, exposure of private posts, drafts, and moderated content across tenants violates user privacy and GDPR/CCPA obligations.

**Evidence from HAR:**
- Request: `POST https://api.horizon-social-graph.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-9c9c`
- Query: `listPosts(tenantId: "tenant-fe91") { postId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-fe91"`, `ownerId: "other-user-9c9cfe91"`, `sensitiveField: "CONFIDENTIAL-9c9cfe91"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-9c9cfe91`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-211 | getPost resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 3.3 | Semantic ambiguity — over-broad listPosts endpoint |
| HAR query | tenantId: "tenant-fe91" | Injected cross-tenant post filter |
| HAR response | tenantId | tenant-fe91 returned to tenant-9c9c |
| HAR response | sensitiveField | CONFIDENTIAL-9c9cfe91 |
| HAR header | x-request-id | req-9c9cfe91 |

## Steps to Reproduce

### Step 1 — listPosts semantic ambiguity cross-tenant (HAR)
```bash
curl -s -X POST https://api.horizon-social-graph.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-9c9c" \
  -d '{"query": "query { listPosts(tenantId: \"tenant-fe91\") { postId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-fe91` private post data including `CONFIDENTIAL-9c9cfe91`. **Secure:** FORBIDDEN — `tenantId` from JWT; only `tenant-9c9c` posts returned.

## Remediation
1. Ignore caller-supplied `tenantId`; enforce `WHERE tenant_id = $jwt.tenantId` in resolver.
2. Explicitly define endpoint semantics: `listPosts` returns only posts owned by the caller's tenant.
3. Redis cache key: `post:{tenantId}:{postId}`.
