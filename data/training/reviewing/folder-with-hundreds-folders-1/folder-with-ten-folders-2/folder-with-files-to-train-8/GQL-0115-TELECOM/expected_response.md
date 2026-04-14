# Expected Response

## System
- Domain: Telecom / 5G Core
- System: SpectreNet Policy Control
- Example ID: GQL-0115

## Priority Findings

### Finding 1: 5G Telecom — Bulk Resource Lookup Exposes Cross-Tenant Policy Objects (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA / Write Operations Without Ownership Check

**Summary:**
Per §5.0 (Pattern 1.6 — write operations without ownership check): The `bulkResourceLookup` resolver accepts an arbitrary array of resource IDs without verifying that each ID belongs to the caller's tenant. An attacker from `tenant-1eab` queried `bulkResourceLookup(ids: ["R-2115", "R-1115", "R-3115"])` and received 5G policy control objects belonging to `tenant-af55`, including `CONFIDENTIAL-1eabaf55` and `internalNotes: "Internal data exposed"`. In Telecom / 5G Core, unauthorized access to policy control data can expose subscriber QoS rules, network slice configurations, and billing plans.

**Evidence from HAR:**
- Request: `POST https://api.spectrenet-policy-co.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-1eab`
- Query: `bulkResourceLookup(ids: ["R-2115", "R-1115", "R-3115"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-af55"`, `ownerId: "other-user-1eabaf55"`, `sensitiveField: "CONFIDENTIAL-1eabaf55"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-1eabaf55`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.6 | bulkResourceLookup, no write ownership check |
| HAR request | x-tenant-id | Attacker tenant-1eab |
| HAR request | ids array | R-2115, R-1115, R-3115 (cross-tenant IDs) |
| HAR response | tenantId | Cross-tenant tenant-af55 returned |

## Steps to Reproduce

### Step 1 — Bulk resource lookup with cross-tenant IDs (HAR)
```bash
curl -s -X POST https://api.spectrenet-policy-co.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-1eab" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2115\", \"R-1115\", \"R-3115\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-af55` 5G policy data returned. **Secure:** Only `tenant-1eab` data returned or FORBIDDEN.

## Remediation
1. Filter all bulk lookups server-side: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Limit bulk lookup array size.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
4. Audit log all bulk lookups with `x-request-id`.
