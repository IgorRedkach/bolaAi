# Expected Response

## System
- Domain: Travel / Global Distribution System
- System: SkyPort Global Distribution
- Example ID: GQL-0168

## Priority Findings

### Finding 1: Travel GDS — Bulk Lookup Persistence Poisoning via Lifecycle Actions (Pattern 4.2)
**Severity:** High
**Category:** Integrity / Persistence Poisoning via Lifecycle Actions

**Summary:**
Per §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions): The `bulkResourceLookup` resolver accepts arbitrary IDs enabling persistence poisoning of booking lifecycle state with cross-tenant data. An attacker from `tenant-31f1` queried `bulkResourceLookup(ids: ["R-2168", "R-1168", "R-3168"])` and received travel booking data belonging to `tenant-60b5`, including `CONFIDENTIAL-31f160b5`. In Travel GDS, this exposes flight bookings, passenger PII, pricing agreements, and loyalty data.

**Evidence from HAR:**
- Request: `POST https://api.skyport-global-distr.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-31f1`
- Query: `bulkResourceLookup(ids: ["R-2168", "R-1168", "R-3168"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-60b5"`, `ownerId: "other-user-31f160b5"`, `sensitiveField: "CONFIDENTIAL-31f160b5"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-31f160b5`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 4.2 | Bulk lookup lifecycle poisoning |
| HAR request | ids array | R-2168, R-1168, R-3168 (cross-tenant) |
| HAR response | tenantId | tenant-60b5 booking data returned |
| HAR response | sensitiveField | CONFIDENTIAL-31f160b5 |

## Steps to Reproduce

### Step 1 — Bulk booking lookup (HAR)
```bash
curl -s -X POST https://api.skyport-global-distr.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-31f1" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2168\", \"R-1168\", \"R-3168\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-60b5` booking data returned. **Secure:** Only `tenant-31f1` data or FORBIDDEN.

## Remediation
1. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Lifecycle state transitions must re-validate tenancy at each booking stage.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
