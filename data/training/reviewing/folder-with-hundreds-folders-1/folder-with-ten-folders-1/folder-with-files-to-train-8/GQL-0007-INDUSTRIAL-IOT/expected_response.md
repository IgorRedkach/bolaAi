## System

- System: ManuControl Robotics Fleet v2.8.8
- Domain: INDUSTRIAL IOT / MANUFACTURING
- Example ID: GQL-0007
- Risk ID: RISK-GQL-007

## Findings

### 1. BOLA on `listResources` — Client-Controlled `tenantId` Argument (Pattern 1.5 / 1.8)

The HAR shows `listResources(tenantId: "tenant-a5a7")` from JWT `tenant-1c38`. Section 5.0 describes Pattern 1.8 (Predictable/Sequential IDs): the `resourceId` field follows a sequential pattern (`R-1007`, `R-2007`, ...) that enables enumeration without the `listResources` bypass. However, the HAR demonstrates a more direct attack: the `listResources` resolver accepts a client-supplied `tenantId` argument and returns the full resource list for any target tenant.

**HAR evidence**: JWT `x-tenant-id: tenant-1c38`. Request: `listResources(tenantId: "tenant-a5a7")`. Response: HTTP 200 OK with `"tenantId": "tenant-a5a7"`, `"sensitiveField": "CONFIDENTIAL-1c38a5a7"`, `"internalNotes": "Internal data exposed"` — industrial IoT resource data for a competing manufacturing operator.

**IIoT/manufacturing impact**: `Resource` objects with `items: [Item!]` in a robotics fleet platform likely represent robot arm configurations, OPC-UA node mappings, or production run parameters. Cross-tenant access exposes manufacturing process parameters and potentially safety-critical robot configurations.

### 2. Pattern 1.8 — Sequential `resourceId` Enables Enumeration

Section 5.0 states Pattern 1.8 (Predictable/Sequential IDs). The HAR uses `R-2007` for the target tenant's resource. The sequential `R-NNNN` pattern means an attacker can enumerate all resource IDs across tenants by incrementing the counter without needing to exploit `listResources`.

### 3. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-007)

Section 4.0 (RISK-GQL-007): `getResource` resolver lacks tenant check — any guessed sequential `resourceId` returns the full record.

### 4. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — accepts arbitrary IDs without per-ID filtering.

### 5. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key.

## Evidence

- **HAR**: `listResources(tenantId: "tenant-a5a7")` with `tenant-1c38` JWT → HTTP 200 → `tenantId: tenant-a5a7` with `sensitiveField`.
- **Section 5.0**: Pattern 1.8 — sequential `R-NNNN` IDs.
- **Section 4.0 (RISK-GQL-007)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1007") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-1c38"`.

**Step 2 — `listResources` tenant override (primary HAR attack):**

```graphql
query { listResources(tenantId: "tenant-a5a7") { resourceId ownerId data { sensitiveField internalNotes } } }
```

Expected secure: restricted to authenticated user's tenant.  
Expected vulnerable: HTTP 200 with full IIoT resource list for `tenant-a5a7`.

**Step 3 — Sequential ID enumeration (Pattern 1.8):**

```graphql
query { getResource(id: "R-2007") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

Repeat with `R-2001` through `R-9999` to enumerate all tenants' resources without tenant argument.  
Expected secure: HTTP 403/404 for cross-tenant IDs.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-a5a7"` data.

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2007", "R-3007", "R-4007"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Ignore client-supplied `tenantId` in `listResources`**: always use JWT `tenantId`.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-007).
- **Replace sequential `R-NNNN` IDs with UUID v4**: eliminates Pattern 1.8 enumeration.
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
