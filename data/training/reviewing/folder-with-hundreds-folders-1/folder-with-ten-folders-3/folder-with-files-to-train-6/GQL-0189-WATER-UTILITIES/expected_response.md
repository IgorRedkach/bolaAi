# Expected Response

## System
- **Domain:** Water Utilities / Smart Grid Infrastructure
- **System:** AquaGrid Meter Management
- **Example ID:** GQL-0189

## Priority Findings

### Finding 1: Water Utilities — Insecure Design via Semantic Ambiguity in bulkResourceLookup Exposes Cross-Tenant Meter Data (Pattern 3.3)
**Severity:** High
**Category:** Insecure Design / Semantic Ambiguity / Over-Broad Endpoints

**Summary:**
Per §4.0 (RISK-GQL-189): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 3.3 — semantic ambiguity/over-broad endpoints): the `bulkResourceLookup` endpoint's semantics are ambiguous regarding ownership scope, allowing cross-tenant meter data retrieval when IDs from other tenants are supplied. An attacker from `tenant-a855` queried `bulkResourceLookup(ids: ["R-2189", "R-1189", "R-3189"])` and received meter records belonging to `tenant-f398`, including `CONFIDENTIAL-a855f398`. In Water Utilities / Smart Grid, exposure of meter calibration data, consumption records, and infrastructure topology poses a public safety and national infrastructure risk.

**Evidence from HAR:**
- Request: `POST https://api.aquagrid-meter-manag.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-a855`
- Query: `bulkResourceLookup(ids: ["R-2189", "R-1189", "R-3189"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-f398"`, `ownerId: "other-user-a855f398"`, `sensitiveField: "CONFIDENTIAL-a855f398"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-a855f398`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-189 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 3.3 | Semantic ambiguity — over-broad bulk endpoint |
| HAR query | ids array | R-2189 cross-tenant meter lookup |
| HAR response | tenantId | tenant-f398 returned to tenant-a855 |
| HAR response | sensitiveField | CONFIDENTIAL-a855f398 |
| HAR header | x-request-id | req-a855f398 |

## Steps to Reproduce

### Step 1 — bulkResourceLookup semantic ambiguity cross-tenant (HAR)
```bash
curl -s -X POST https://api.aquagrid-meter-manag.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a855" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2189\", \"R-1189\", \"R-3189\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-f398` water meter record including `CONFIDENTIAL-a855f398`. **Secure:** FORBIDDEN — only `tenant-a855` meters returned.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Redefine endpoint semantics explicitly: `bulkMeterLookup` only returns meters owned by the caller's `tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
