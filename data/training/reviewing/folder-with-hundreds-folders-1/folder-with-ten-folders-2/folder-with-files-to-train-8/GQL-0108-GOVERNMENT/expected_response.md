# Expected Response

## System
- Domain: Government / Public Safety
- System: FirstResponse CAD Integration
- Example ID: GQL-0108

## Priority Findings

### Finding 1: Government CAD — ID Swap Exposes Cross-Tenant Dispatch Records (Pattern 10.1)
**Severity:** Critical
**Category:** Single-User / ID Swap in Own Request

**Summary:**
Per §5.0 (Pattern 10.1 — ID swap in own request): The `listResources` resolver accepts a client-supplied `tenantId` filter and returns records for any tenant rather than restricting to the caller's JWT-bound tenancy. An attacker from `tenant-0417` passed `tenantId: "tenant-8f38"` and received CAD dispatch records belonging to `tenant-8f38`, including `CONFIDENTIAL-04178f38` and `internalNotes: "Internal data exposed"`. In Government / Public Safety, unauthorized access to CAD integration data can expose emergency dispatch identifiers, officer locations, and incident details.

**Evidence from HAR:**
- Request: `POST https://api.firstresponse-cad-in.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-0417`
- Query: `listResources(tenantId: "tenant-8f38") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-8f38"`, `ownerId: "other-user-04178f38"`, `sensitiveField: "CONFIDENTIAL-04178f38"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-04178f38`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.1 | listResources accepts client-supplied tenantId |
| HAR request | x-tenant-id | Attacker tenant-0417 |
| HAR request body | tenantId argument | tenant-8f38 (victim) |
| HAR response | sensitiveField | CONFIDENTIAL-04178f38 |

## Steps to Reproduce

### Step 1 — listResources ID swap (HAR)
```bash
curl -s -X POST https://api.firstresponse-cad-in.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-0417" \
  -d '{"query": "query { listResources(tenantId: \"tenant-8f38\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-8f38` CAD data returned. **Secure:** Only `tenant-0417` data returned.

## Remediation
1. Resolver must ignore client-supplied `tenantId`; derive from `$jwt.tenantId` only.
2. Row-level security: `WHERE tenant_id = current_setting('app.tenant_id')`.
3. Remove `tenantId` filter argument from `listResources` GraphQL schema.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
