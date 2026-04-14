## System

- System: StreamCore VOD Platform v1.8.4
- Domain: MEDIA / CONTENT DELIVERY
- Example ID: GQL-0019
- Risk ID: RISK-GQL-019

## Findings

### 1. Cross-Tenant Write via Single Endpoint — `updateResource` Without Per-Operation Authorization (Pattern 9.1 / HAR Primary)

**Primary HAR attack**: The HAR shows `updateResource(id: "R-2019", input: {status: "approved", ownerId: "attacker-a0c15440"})` from JWT `tenant-a0c1`.

**Pattern 9.1 (Platform — GraphQL Single Endpoint)**:  section 5.0 describes this as: all GraphQL operations (queries AND mutations) arrive at `POST /graphql`. Unlike REST, where different paths or HTTP methods can carry different authorization policies, the single-endpoint design means mutations like `updateResource` and `deleteResource` share the same URL and transport as read queries. Per-operation authorization must be enforced at the resolver level — not the HTTP layer. Because it is missing here, any authenticated caller can issue write mutations against any `resourceId` regardless of tenant ownership.

**HAR evidence**: JWT `x-tenant-id: tenant-a0c1`. Request: `updateResource(id: "R-2019", input: {status: "approved", ownerId: "attacker-a0c15440"})`. Response: HTTP 200 OK with `"tenantId": "tenant-5440"` — write mutation against a cross-tenant VOD content resource accepted.

**Media/VOD impact**: `Resource` objects in a video-on-demand platform represent content assets, DRM licenses, or streaming configurations. An attacker from one media company can approve another company's unreleased content (bypassing content moderation), reassign content ownership, or alter distribution status — constituting content rights theft and platform integrity violation.

### 2. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-019)

Section 4.0 (RISK-GQL-019): `getResource` fetches by `resourceId` without tenant check.

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkResourceLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key.

## Evidence

- **HAR**: `updateResource(id: "R-2019", input: {status: "approved", ownerId: "attacker-a0c15440"})` with `tenant-a0c1` JWT → HTTP 200 with `tenantId: tenant-5440`.
- **Section 5.0**: Pattern 9.1 — single endpoint; per-operation authorization absent for write mutations.
- **Section 4.0 (RISK-GQL-019)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1019") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-a0c1"`.

**Step 2 — Cross-tenant write mutation at single endpoint — approve and transfer content (primary HAR attack):**

```graphql
mutation {
  updateResource(id: "R-2019", input: {
    status: "approved",
    ownerId: "attacker-a0c15440"
  }) {
    resourceId status tenantId ownerId
  }
}
```

Expected secure: Mutation rejected — per-operation authorization blocks cross-tenant write.  
Expected vulnerable: HTTP 200 — content asset `R-2019` from `tenant-5440` approved and ownership transferred to attacker, all via the same `POST /graphql` endpoint as a read query.

**Step 3 — Cross-tenant content delete at single endpoint:**

```graphql
mutation { deleteResource(id: "R-2019") }
```

Expected secure: `false` or authorization error.  
Expected vulnerable: `true` — competitor's content permanently deleted.

**Step 4 — Cross-tenant read (RISK-GQL-019):**

```graphql
query { getResource(id: "R-2019") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

**Step 5 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2019", "R-3019", "R-4019"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Per-operation resolver-level authorization for all mutations**: `updateResource` and `deleteResource` must verify `resource.tenantId == jwt.tenantId` independently — HTTP-layer restrictions are insufficient for GraphQL single-endpoint architectures.
- **Strip `ownerId` from mutation input**: not a user-settable field.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-019).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
