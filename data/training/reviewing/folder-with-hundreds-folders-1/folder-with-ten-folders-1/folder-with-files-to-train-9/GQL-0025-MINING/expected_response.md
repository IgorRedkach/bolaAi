## System

- System: OreTrack Fleet Management v1.5.8
- Domain: MINING / RESOURCE EXTRACTION
- Example ID: GQL-0025
- Risk ID: RISK-GQL-025

## Findings

### 1. Pattern 1.3 — Bulk/List Endpoint `listResources` Returns Cross-Tenant Fleet Data

**Primary Pattern 1.3 attack**: Section 5.0 describes Pattern 1.3: "The `listResources` resolver returns all objects when the `tenantId` filter is omitted or when it is supplied from the client without JWT-level validation." Two distinct attacks:

**(a) Omit `tenantId` to list all tenants' fleet data**: `listResources` with no `tenantId` filter returns all mining fleet resources across all tenants — exposing every operator's asset inventory.

**(b) Supply competitor's `tenantId` to list their fleet data**: `listResources(tenantId: "tenant-7caa")` returns the complete mining fleet of a competing operator.

**Mining/Fleet impact**: `Resource` objects in OreTrack represent mining vehicles, drilling rigs, or extraction site records. `items: [Item!]` = telemetry readings (GPS position, fuel consumption, ore throughput). Bulk list access without tenant enforcement exposes a competitor's entire fleet location data, equipment status, and operational schedule — enabling targeted sabotage or competitor intelligence.

### 2. BOLA on `getResource` — Single-ID Without Ownership Check (RISK-GQL-025 / HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-44e7`. Request: `getResource(id: "R-2025")`. Response: HTTP 200 OK with `"tenantId": "tenant-7caa"`, `"sensitiveField": "CONFIDENTIAL-44e77caa"` — single cross-tenant fleet asset returned.

Section 4.0 (RISK-GQL-025): `getResource` fetches by `resourceId` without tenant check.

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter

Section 4.0: documented gap.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key. Fleet telemetry cached without tenant dimension could expose competitor's real-time vehicle positions.

## Evidence

- **HAR**: `getResource(id: "R-2025")` with `tenant-44e7` JWT → HTTP 200 → `tenantId: tenant-7caa` with `sensitiveField`.
- **Section 5.0**: Pattern 1.3 — `listResources` returns cross-tenant data when `tenantId` omitted or supplied by client.
- **Section 4.0 (RISK-GQL-025)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1025") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-44e7"`.

**Step 2a — `listResources` with no `tenantId` — dump all tenants' fleet data (Pattern 1.3):**

```graphql
query { listResources { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

Expected secure: Returns only records for JWT `tenantId`.  
Expected vulnerable: All mining fleet resources across ALL tenants.

**Step 2b — `listResources` with competitor `tenantId` (Pattern 1.3 client-controlled filter):**

```graphql
query { listResources(tenantId: "tenant-7caa") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

Expected secure: Ignores client-supplied `tenantId`; returns own records only.  
Expected vulnerable: HTTP 200 with complete fleet inventory for `tenant-7caa`.

**Step 3 — Single cross-tenant fleet asset read (RISK-GQL-025 / primary HAR attack):**

```graphql
query { getResource(id: "R-2025") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

**Step 4 — Bulk cross-tenant fleet lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2025", "R-3025", "R-4025"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce JWT `tenantId` in `listResources`**: ignore client-supplied `tenantId`; always use `WHERE tenant_id = jwt.tenantId`. Never allow cross-tenant list expansion through client parameters.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-025).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
