# Expected Response

## System
- **Domain:** Travel / Global Distribution
- **System:** SkyPort Global Distribution
- **Example ID:** GQL-0218

## Priority Findings

### Finding 1: Travel GDS — Single-User ID Swap via bulkResourceLookup Exposes Cross-Tenant Booking Data (Pattern 10.1)
**Severity:** High
**Category:** Single-User / ID Swap in Own Request

**Summary:**
Per §4.0 (RISK-GQL-218): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 10.1 — ID swap in own request): the `bulkResourceLookup` operation allows a user to swap resource IDs in their own bulk request to ones belonging to other tenants, bypassing ownership checks. An attacker from `tenant-8af0` queried `bulkResourceLookup(ids: ["R-2218", "R-1218", "R-3218"])` and received travel booking data belonging to `tenant-4ebb`, including `CONFIDENTIAL-8af04ebb`. In Travel / Global Distribution, unauthorized access to booking records, passenger data, and fare configurations enables PII exposure and travel fraud.

**Evidence from HAR:**
- Request: `POST https://api.skyport-global-distr.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-8af0`
- Query: `bulkResourceLookup(ids: ["R-2218", "R-1218", "R-3218"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-4ebb"`, `ownerId: "other-user-8af04ebb"`, `sensitiveField: "CONFIDENTIAL-8af04ebb"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-8af04ebb`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-218 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 10.1 | ID swap in own bulk request |
| HAR query | ids: ["R-2218"...] | Cross-tenant booking ID swap |
| HAR response | tenantId | tenant-4ebb returned to tenant-8af0 |
| HAR response | sensitiveField | CONFIDENTIAL-8af04ebb |
| HAR header | x-request-id | req-8af04ebb |

## Steps to Reproduce

### Step 1 — bulkResourceLookup ID swap cross-tenant travel (HAR)
```bash
curl -s -X POST https://api.skyport-global-distr.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8af0" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2218\", \"R-1218\", \"R-3218\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-4ebb` booking data including `CONFIDENTIAL-8af04ebb`. **Secure:** FORBIDDEN — only `tenant-8af0` records returned.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Discard any result where `tenant_id != jwt.tenantId` before returning bulk response.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
