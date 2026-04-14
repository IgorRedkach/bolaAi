# Expected Response

## System
- Domain: Social Media / Identity Graph
- System: Horizon Social Graph API
- Example ID: GQL-0111

## Priority Findings

### Finding 1: Social Media — Post ID Swap Exposes Cross-Tenant Social Graph Data (Pattern 1.1)
**Severity:** High
**Category:** BOLA / ID in Path Without Ownership Check

**Summary:**
Per §4.0 RISK-GQL-111 and §5.0 (Pattern 1.1 — ID in path without ownership check): The `getPost` resolver accepts `postId` from the query without verifying ownership. An attacker from `tenant-93af` issued `updatePost(id: "P-2111", input: {status: "approved", ownerId: "attacker-93afd127"})` against a post belonging to `tenant-d127`, gaining cross-tenant social graph write access and receiving `CONFIDENTIAL-93afd127`. In Social Media, this enables unauthorized modification of social identity data, user posts, and relationship graph objects.

**Evidence from HAR:**
- Request: `POST https://api.horizon-social-graph.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-93af`
- Mutation: `updatePost(id: "P-2111", input: {status: "approved", ownerId: "attacker-93afd127"}) { postId status }`
- Response `200 OK`: `tenantId: "tenant-d127"`, `ownerId: "other-user-93afd127"`, `sensitiveField: "CONFIDENTIAL-93afd127"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-93afd127`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-111 | getPost accepts postId without ownership check |
| HAR request | x-tenant-id | Attacker tenant-93af |
| HAR request | input.ownerId | attacker-93afd127 (client-injected) |
| HAR response | tenantId | Cross-tenant tenant-d127 data returned |

## Steps to Reproduce

### Step 1 — updatePost with cross-tenant post ID (HAR)
```bash
curl -s -X POST https://api.horizon-social-graph.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-93af" \
  -d '{"query": "mutation { updatePost(id: \"P-2111\", input: {status: \"approved\", ownerId: \"attacker-93afd127\"}) { postId status } }"}'
```
**Vulnerable:** `tenant-d127` social post mutated. **Secure:** FORBIDDEN.

## Remediation
1. `getPost` resolver: `WHERE post_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `PostInput`; set from `$jwt.userId` server-side.
3. Redis cache key: `post:{tenantId}:{postId}`.
