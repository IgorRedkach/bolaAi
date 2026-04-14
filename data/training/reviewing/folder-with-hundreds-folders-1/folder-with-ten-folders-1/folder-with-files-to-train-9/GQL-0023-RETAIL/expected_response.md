## System

- System: RewardCore Loyalty API v3.0.9
- Domain: RETAIL / LOYALTY PROGRAMME
- Example ID: GQL-0023
- Risk ID: RISK-GQL-023

## Findings

### 1. BOLA — ID in GraphQL Argument Without Ownership Check, Exploited via Write Mutation (Pattern 1.1 / HAR Primary)

**Primary HAR attack**: The HAR shows `updateResource(id: "R-2023", input: {status: "approved", ownerId: "attacker-c01b576a"})` from JWT `tenant-c01b`. Section 5.0 describes Pattern 1.1: the `getResource` resolver (and by extension all resolvers using the same `resourceId` argument) accepts the ID without verifying ownership. In the HAR, this is demonstrated through a write mutation — the `updateResource` resolver shares the same unguarded ID argument, enabling cross-tenant writes.

**HAR evidence**: JWT `x-tenant-id: tenant-c01b`. Request: `updateResource(id: "R-2023", input: {status: "approved", ownerId: "attacker-c01b576a"})`. Response: HTTP 200 OK with `"tenantId": "tenant-576a"` — a loyalty account or reward record belonging to another retailer's tenant approved and ownership transferred.

**Retail/Loyalty Programme impact**: `Resource` objects in a loyalty platform represent member accounts, reward redemption requests, or promotional campaign allocations. `updateResource(status: "approved")` on a cross-tenant `resourceId` approves a pending reward redemption without authorization — enabling fraudulent points burning from another retailer's loyalty ledger. Combined with `ownerId` transfer, the attacker gains control of the reward record.

### 2. BOLA on `getResource` — ID Argument Without Ownership Check (RISK-GQL-023 / Pattern 1.1 Canonical)

Section 5.0 and Section 4.0 (RISK-GQL-023): `getResource` directly fetches by `resourceId` without checking `WHERE tenant_id = jwt.tenantId`. This is the canonical Pattern 1.1 — a single ID substitution in the argument returns any loyalty account.

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter

Section 4.0: documented gap.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key. Loyalty account records cached without tenant dimension could serve cross-retailer data.

## Evidence

- **HAR**: `updateResource(id: "R-2023", input: {status: "approved", ownerId: "attacker-c01b576a"})` with `tenant-c01b` JWT → HTTP 200 with `tenantId: tenant-576a`.
- **Section 5.0**: Pattern 1.1 — `resourceId` argument accepted without ownership check in any resolver.
- **Section 4.0 (RISK-GQL-023)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1023") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-c01b"`.

**Step 2 — Cross-tenant write + ownership transfer (primary HAR attack — Pattern 1.1 on mutation):**

```graphql
mutation {
  updateResource(id: "R-2023", input: {
    status: "approved",
    ownerId: "attacker-c01b576a"
  }) {
    resourceId status tenantId ownerId
  }
}
```

Expected secure: Mutation rejected — `R-2023` belongs to `tenant-576a`, not the JWT's `tenant-c01b`.  
Expected vulnerable: HTTP 200 — another retailer's reward record approved, ownership transferred to attacker.

**Step 3 — Single cross-tenant loyalty account read (Pattern 1.1 canonical / RISK-GQL-023):**

```graphql
query { getResource(id: "R-2023") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

**Step 4 — Bulk cross-tenant loyalty records lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2023", "R-3023", "R-4023"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in all resolvers** (RISK-GQL-023): `WHERE resourceId = $id AND tenant_id = jwt.tenantId` — the root fix for Pattern 1.1.
- **Enforce cross-tenant check before `updateResource`**: check ownership before applying any mutation.
- **Strip `ownerId` from mutation input**: server-controlled only.
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
