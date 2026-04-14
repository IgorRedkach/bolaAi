## System

- System: AetherDrive V2X Telematics v2.5.0
- Domain: AUTOMOTIVE / CONNECTED CAR
- Example ID: GQL-0005
- Risk ID: RISK-GQL-005

## Findings

### 1. BOLA on `listResources` — Client-Controlled `tenantId` Argument (Pattern 1.5)

HAR shows `listResources(tenantId: "tenant-7490")` with JWT `tenant-93ec`. Section 5.0: "The `updateResource` mutation accepts an arbitrary `resourceId` without verifying ownership." The `listResources` resolver accepts and trusts the client-supplied `tenantId` argument, returning all resources for the target fleet operator.

**HAR evidence**: JWT `x-tenant-id: tenant-93ec`. Request: `listResources(tenantId: "tenant-7490")`. Response: HTTP 200 OK with `"tenantId": "tenant-7490"`, `"sensitiveField": "CONFIDENTIAL-93ec7490"`, `"internalNotes": "Internal data exposed"`.

### 2. BOLA on `updateResource` — Write Without Ownership Check (Pattern 1.6, primary stated)

Section 5.0: "The `updateResource` mutation accepts an arbitrary `resourceId` in the path without verifying the requester owns that object." In a V2X platform, an unauthorized write can modify a vehicle's telemetry configuration or OTA routing.

### 3. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-005)

Section 4.0 (RISK-GQL-005): `getResource` fetches by `resourceId` only — no `tenantId` check.

### 4. BOLA on `bulkResourceLookup` — No Per-ID Filter (Pattern 1.9)

Section 4.0: "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

### 5. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)."

## Evidence

- **HAR**: `listResources(tenantId: "tenant-7490")` with `tenant-93ec` JWT → HTTP 200 → `tenantId: tenant-7490` with `sensitiveField`.
- **Section 5.0**: `updateResource` lacks ownership check.
- **Section 4.0 (RISK-GQL-005)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1005") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-93ec"`.

**Step 2 — `listResources` tenant override (primary HAR attack):**

```graphql
query { listResources(tenantId: "tenant-7490") { resourceId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: restricted to authenticated user's tenant.  
Expected vulnerable outcome: HTTP 200 with full resource listing for `tenant-7490`.

**Step 3 — Cross-tenant write (Pattern 1.6 stated vulnerability):**

```graphql
mutation { updateResource(id: "R-2005", input: { status: "disabled", data: { title: "corrupted" } }) { resourceId tenantId status } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"updateResource": null}}`.  
Expected vulnerable outcome: HTTP 200 with write applied to `tenant-7490` vehicle resource.

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2005", "R-3005", "R-4005"]) { resourceId tenantId data { sensitiveField } } }
```

Expected vulnerable outcome: HTTP 200 with cross-tenant V2X telemetry data.

## Remediation

- **Ignore client-supplied `tenantId` in `listResources`**: always use JWT `tenantId`.
- **Enforce ownership check in `updateResource`** (Pattern 1.6): verify `resource.tenantId == jwtTenantId` before mutation.
- **Add `tenant_id` WHERE clause to `getResource`** (RISK-GQL-005).
- **Filter `bulkResourceLookup` results by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
