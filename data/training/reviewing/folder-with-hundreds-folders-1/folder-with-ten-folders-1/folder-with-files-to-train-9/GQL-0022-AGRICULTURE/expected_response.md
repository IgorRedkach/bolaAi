## System

- System: HarvestIQ IoT Platform v4.1.7
- Domain: AGRICULTURE / PRECISION FARMING
- Example ID: GQL-0022
- Risk ID: RISK-GQL-022

## Findings

### 1. Cross-Tenant Write Promoting Draft Resource — `updateResource` status: "approved" (Pattern 10.5 / HAR Primary)

**Primary HAR attack**: The HAR shows `updateResource(id: "R-2022", input: {status: "approved", ownerId: "attacker-788421de"})` from JWT `tenant-7884`. Pattern 10.5 (Draft/Non-Published Resource Access) in its most damaging form: the attacker not only reads another farming operator's unpublished (draft) resource but promotes it to "approved" — publishing it without authorization. Combined with `ownerId` transfer, the attacker takes ownership of the victim's draft content.

**HAR evidence**: JWT `x-tenant-id: tenant-7884`. Request: `updateResource(id: "R-2022", input: {status: "approved", ownerId: "attacker-788421de"})`. Response: HTTP 200 OK with `"tenantId": "tenant-21de"` — cross-tenant draft IoT configuration resource approved and ownership transferred to attacker.

**Agriculture/Precision Farming impact**: `Resource` objects with `items: [Item!]` in a precision farming platform represent field sensor configurations, crop yield models, or agricultural chemical application schedules. Draft resources may contain unreleased proprietary crop prediction models, pre-season planting strategies, or pending pesticide schedules that competitors could exploit. Unauthorized status promotion (`draft` → `approved`) activates pending IoT commands on the victim's farm sensors.

### 2. Draft Resource Enumeration via `listResources(status: "draft")` (Pattern 10.5)

Pattern 10.5 also includes the discovery phase: using `listResources` with `status: "draft"` and a target `tenantId` to enumerate all unpublished/draft resources of another farming operator before accessing or modifying them.

### 3. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-022)

Section 4.0 (RISK-GQL-022): `getResource` fetches by `resourceId` without tenant check.

### 4. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter

Section 4.0: documented gap.

### 5. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key.

## Evidence

- **HAR**: `updateResource(id: "R-2022", input: {status: "approved", ownerId: "attacker-788421de"})` with `tenant-7884` JWT → HTTP 200 with `tenantId: tenant-21de`.
- **Section 5.0**: Pattern 10.5 — draft/non-published resource access; resolver lacks status + ownership enforcement.
- **Section 4.0 (RISK-GQL-022)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1022") { resourceId tenantId status data { sensitiveField } } }
```

Expected: `tenantId: "tenant-7884"`.

**Step 2 — Draft resource enumeration across tenants (Pattern 10.5 discovery):**

```graphql
query { listResources(tenantId: "tenant-21de", status: "draft") { resourceId tenantId status ownerId data { sensitiveField internalNotes } } }
```

Expected secure: Ignores client-supplied `tenantId`; returns only own draft records.  
Expected vulnerable: HTTP 200 with all unpublished resources for `tenant-21de`, including proprietary crop models in draft state.

**Step 3 — Approve and transfer ownership of cross-tenant draft resource (primary HAR attack):**

```graphql
mutation {
  updateResource(id: "R-2022", input: {
    status: "approved",
    ownerId: "attacker-788421de"
  }) {
    resourceId status tenantId ownerId
  }
}
```

Expected secure: Mutation rejected — cross-tenant access blocked.  
Expected vulnerable: HTTP 200 — draft crop/sensor configuration from `tenant-21de` published and transferred to attacker.

**Step 4 — Single cross-tenant draft read (RISK-GQL-022):**

```graphql
query { getResource(id: "R-2022") { resourceId tenantId status ownerId data { sensitiveField internalNotes } items { itemId } } }
```

**Step 5 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2022", "R-3022", "R-4022"]) { resourceId tenantId status data { sensitiveField } } }
```

## Remediation

- **Enforce cross-tenant check before `updateResource`**: verify `resource.tenantId == jwt.tenantId` before any status transition.
- **Restrict `status` transitions to authorized roles**: `approved` state transition must require an explicit workflow role — not a plain user input.
- **Ignore client-supplied `tenantId` in `listResources`**: source from JWT only.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-022).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
