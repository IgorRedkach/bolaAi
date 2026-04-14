## System

- System: ShopGrid Marketplace API v5.0.7
- Domain: E-COMMERCE / MARKETPLACE
- Example ID: GQL-0003
- Risk ID: RISK-GQL-003

## Findings

### 1. BOLA on `bulkOrderLookup` — No Per-ID Tenant Ownership Filter (Pattern 1.3 / 1.9)

The HAR shows `bulkOrderLookup(ids: ["O-2003", "O-1003", "O-3003"])` from JWT `tenant-1ffe`. Section 4.0 documents: "The `bulkOrderLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." HTTP 200 is returned with order records from `tenant-7a2b`.

**HAR evidence**: JWT `x-tenant-id: tenant-1ffe`. Bulk lookup mutation. Response: HTTP 200 OK. Response `"tenantId": "tenant-7a2b"` with `"sensitiveField": "CONFIDENTIAL-1ffe7a2b"` — order PII from `tenant-7a2b` returned to `tenant-1ffe`.

### 2. BOLA on `getOrder` — Missing `tenant_id` Filter (Pattern 1.1, RISK-GQL-003)

Section 4.0 (RISK-GQL-003): "The `getOrder` resolver fetches by `orderId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`."

### 3. BOLA on `listOrders` — Client-Controlled `tenantId` Argument (Pattern 1.3)

Section 5.0: "The `listOrders` resolver returns all objects when the `tenantId` filter is omitted or when it is supplied from the client without JWT-level validation." The schema exposes `listOrders(tenantId: ID, status: String)` — an attacker supplies a competitor's `tenantId` to list all their orders.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `orderId` (NOTE: no user dimension in cache key)."

## Evidence

- **HAR**: `bulkOrderLookup` with `tenant-1ffe` JWT → HTTP 200 → `tenantId: tenant-7a2b` with `sensitiveField`.
- **Section 4.0 (RISK-GQL-003)**: `getOrder` resolver lacks tenant check — documented.
- **Section 4.0**: `bulkOrderLookup` lacks per-ID ownership filter — documented.
- **Section 5.0**: `listOrders` accepts client-controlled `tenantId` without JWT validation.
- **Section 2.0**: Redis cache keyed by `orderId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getOrder(id: "O-1003") { orderId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-1ffe"` — attacker's own order.

**Step 2 — Bulk cross-tenant lookup (primary HAR attack):**

```graphql
mutation { bulkOrderLookup(ids: ["O-2003", "O-1003", "O-3003"]) { orderId tenantId data { sensitiveField } } }
```

Expected secure outcome: only `tenant-1ffe` orders returned.  
Expected vulnerable outcome: HTTP 200 with `tenant-7a2b` orders.

**Step 3 — `listOrders` tenant override:**

```graphql
query { listOrders(tenantId: "tenant-7a2b") { orderId tenantId data { sensitiveField } } }
```

Expected secure outcome: restricted to authenticated user's tenant.  
Expected vulnerable outcome: full order list for `tenant-7a2b`.

**Step 4 — Single cross-tenant `getOrder`:**

```graphql
query { getOrder(id: "O-2003") { orderId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"getOrder": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-7a2b"`.

## Remediation

- **Ignore client-supplied `tenantId` in `listOrders`**: always use JWT `tenantId`.
- **Add `tenant_id` WHERE clause to `getOrder` resolver** (RISK-GQL-003).
- **Filter `bulkOrderLookup` results**: exclude records where `tenant_id != jwtTenantId`.
- **Add `tenantId` to Redis cache key**.
- **Scope write mutations (`updateOrder`, `deleteOrder`) to JWT tenant**.
