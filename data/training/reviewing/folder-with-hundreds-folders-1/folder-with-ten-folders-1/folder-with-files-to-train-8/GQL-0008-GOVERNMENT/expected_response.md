## System

- System: FirstResponse CAD Integration v1.2.9
- Domain: GOVERNMENT / PUBLIC SAFETY
- Example ID: GQL-0008
- Risk ID: RISK-GQL-008

## Findings

### 1. BOLA on `bulkResourceLookup` — Batch Cross-Tenant Lookup Without Ownership Filter (Pattern 1.9)

**Primary HAR attack**: The HAR shows `bulkResourceLookup(ids: ["R-2008", "R-1008", "R-3008"])` from JWT `tenant-33ca`. Section 5.0 explicitly describes Pattern 1.9: `bulkResourceLookup` accepts an arbitrary list of IDs without per-ID ownership filtering.

**HAR evidence**: JWT `x-tenant-id: tenant-33ca`. Request: `bulkResourceLookup(ids: ["R-2008", "R-1008", "R-3008"])`. Response: HTTP 200 OK with `"tenantId": "tenant-3662"`, `"sensitiveField": "CONFIDENTIAL-33ca3662"`, `"internalNotes": "Internal data exposed"` — dispatch records belonging to a different public safety agency returned to an unauthorized caller.

**Government/public safety impact**: FirstResponse CAD Integration is a Computer-Aided Dispatch (CAD) system used by emergency services (police, fire, EMS). The `Resource` objects represent incident records, dispatch assignments, or unit status. Cross-agency access exposes active 911 incidents, officer locations, and dispatch coordinates — creating public safety risks if an adversarial actor uses this to locate or counteract emergency responders.

### 2. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-008)

Section 4.0 (RISK-GQL-008): `getResource` resolver lacks tenant check — any `resourceId` returns the full record regardless of the caller's agency (`tenantId`).

### 3. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `resourceId` only — no `tenantId` in the cache key. A cached response for `R-2008` (belonging to `tenant-3662`) served from cache to `tenant-33ca` bypasses any server-side auth check that might otherwise exist.

## Evidence

- **HAR**: `bulkResourceLookup(ids: ["R-2008", "R-1008", "R-3008"])` with `tenant-33ca` JWT → HTTP 200 → `tenantId: tenant-3662` with `sensitiveField`.
- **Section 5.0**: Pattern 1.9 — `bulkResourceLookup` lacks per-ID ownership checks.
- **Section 4.0 (RISK-GQL-008)**: `getResource` lacks tenant check.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1008") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-33ca"`.

**Step 2 — Bulk cross-tenant batch lookup (primary HAR attack):**

```graphql
mutation { bulkResourceLookup(ids: ["R-2008", "R-1008", "R-3008"]) { resourceId tenantId data { sensitiveField internalNotes } } }
```

Expected secure: Only returns records where `tenantId` matches the JWT's `tenantId` — foreign IDs silently omitted or returned as null.  
Expected vulnerable: HTTP 200 with records from `tenant-3662` and other tenants in a single response.

**Step 3 — Single cross-tenant ID lookup (RISK-GQL-008):**

```graphql
query { getResource(id: "R-2008") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure: HTTP 403/404 or null with authorization error.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-3662"` and full dispatch record.

## Remediation

- **Filter `bulkResourceLookup` by JWT `tenantId`**: after fetching by IDs, remove any result where `tenantId != jwt.tenantId`.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-008).
- **Add `tenantId` to Redis cache key**: `{tenantId}:{resourceId}`.
- **Audit logging**: all cross-agency accesses to dispatch records should be logged with requester identity and target incident ID.
