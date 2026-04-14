## System

- System: AetherDrive V2X Telematics v2.5.0
- Domain: AUTOMOTIVE / CONNECTED CAR
- Example ID: GQL-0005
- Risk ID: RISK-GQL-005

## Findings

### 1. BOLA on `listResources` — Client-Controlled `tenantId` Filter Trusted Over JWT (Pattern 1.5)

The HAR shows the attacker sends `listResources(tenantId: "tenant-7490")` with JWT `tenant-93ec`. The resolver accepts the client-provided `tenantId` query argument and uses it as the database scope instead of the JWT `tenantId` claim. A competitor can supply any operator's `tenantId` to receive the full vehicle resource catalog for that fleet.

**HAR evidence**: JWT header `x-tenant-id: tenant-93ec`. Request query: `listResources(tenantId: "tenant-7490")`. Response: HTTP 200 OK. Response `"tenantId": "tenant-7490"` with `"sensitiveField": "CONFIDENTIAL-93ec7490"` and `"internalNotes": "Internal data exposed"` — V2X telemetry resource data from `tenant-7490` served to `tenant-93ec`.

### 2. BOLA on `updateResource` — Write Without Ownership Check (Pattern 1.6, primary stated pattern)

Section 5.0: "The `updateResource` mutation accepts an arbitrary `resourceId` in the path without verifying the requester owns that object. A write-level BOLA allows state corruption across tenants." The resolver processes mutation inputs for any `resourceId` without comparing the resource's `tenantId` against the JWT's `tenantId`. In a V2X platform, this enables an attacker to overwrite telemetry parameters or OTA routing configuration for vehicles belonging to another fleet operator.

### 3. BOLA on `getResource` — Missing `tenant_id` Filter in Resolver (Pattern 1.1, RISK-GQL-005)

Section 4.0 (RISK-GQL-005): "The `getResource` resolver fetches by `resourceId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." Direct resource lookup is also vulnerable — any known `resourceId` returns the full telemetry record.

### 4. BOLA on `bulkResourceLookup` — No Per-ID Tenant Ownership Filter (Pattern 1.9)

Section 4.0: "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." Cross-tenant batch retrieval of vehicle resources is possible in a single request.

### 5. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." Cross-tenant V2X telemetry data cached without a tenant dimension may be served to subsequent callers.

## Evidence

- **HAR trace**: JWT `x-tenant-id: tenant-93ec` → `listResources(tenantId: "tenant-7490")` → HTTP 200 OK → response `tenantId: tenant-7490` with `sensitiveField` and `internalNotes`.
- **Section 5.0**: `updateResource` mutation accepts arbitrary `resourceId` without ownership verification.
- **Section 4.0 (RISK-GQL-005)**: `getResource` resolver lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID ownership filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Attacker baseline:**

```graphql
query { getResource(id: "R-1005") { resourceId tenantId data { sensitiveField } } }
```

Expected: returns `tenantId: "tenant-93ec"` — attacker's own resource.

**Step 2 — `listResources` tenant override (primary HAR attack):**

```graphql
query { listResources(tenantId: "tenant-7490") { resourceId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: results restricted to authenticated user's tenant regardless of argument.  
Expected vulnerable outcome: HTTP 200 with full resource listing for `tenant-7490`.

**Step 3 — Cross-tenant write (Pattern 1.6 stated vulnerability):**

```graphql
mutation { updateResource(id: "R-2005", input: { status: "disabled", data: { title: "corrupted" } }) { resourceId tenantId status } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"updateResource": null}}`.  
Expected vulnerable outcome: HTTP 200 confirming write applied to `tenant-7490`'s resource with `"tenantId": "tenant-7490"`.

**Step 4 — Single cross-tenant read:**

```graphql
query { getResource(id: "R-2005") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: forbidden error or null.  
Expected vulnerable outcome: full resource data for `tenant-7490`.

## Remediation

- **Ignore client-supplied `tenantId` in `listResources`**: always scope query to JWT `tenantId`; remove `tenantId` as a client-supplied argument or validate it matches the JWT.
- **Enforce `tenant_id` in `updateResource` resolver** (Pattern 1.6): verify `resource.tenantId == jwtTenantId` before applying any mutation — return 403/Forbidden on mismatch.
- **Enforce `tenant_id` in `getResource` resolver** (RISK-GQL-005): `WHERE resourceId = $id AND tenant_id = $jwtTenantId`.
- **Filter `bulkResourceLookup` results post-fetch**: exclude records where `tenant_id != jwtTenantId`.
- **Add `tenantId` to Redis cache key**: change from `resourceId` to `resourceId:tenantId`.
