## System

- System: ShopGrid Marketplace API v5.0.7
- Domain: E-COMMERCE / MARKETPLACE
- Example ID: GQL-0003
- Risk ID: RISK-GQL-003

## Findings

### 1. BOLA on `bulkOrderLookup` — No Per-ID Tenant Ownership Filter (Pattern 1.3 / 1.9)

The HAR shows the attacker sends `bulkOrderLookup(ids: ["O-2003", "O-1003", "O-3003"])` with JWT `tenant-1ffe`. Section 4.0 documents: "The `bulkOrderLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." The mutation processes all supplied IDs and returns results regardless of the tenant ownership of each individual record.

**HAR evidence**: JWT header `x-tenant-id: tenant-1ffe`. Bulk lookup mutation with cross-tenant IDs. Response: HTTP 200 OK. Response body `"tenantId": "tenant-7a2b"` — cross-tenant order returned. `"sensitiveField": "CONFIDENTIAL-1ffe7a2b"` and `"internalNotes": "Internal data exposed"` confirm order data and PII from `tenant-7a2b` returned to `tenant-1ffe`.

### 2. BOLA on `getOrder` — Missing `tenant_id` Filter in Resolver (Pattern 1.1, RISK-GQL-003)

Section 4.0 (RISK-GQL-003): "The `getOrder` resolver fetches by `orderId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." Any authenticated user can substitute any `orderId` to retrieve cross-tenant order records including purchase history and PII.

### 3. BOLA on `listOrders` — Client-Controlled `tenantId` Filter Without JWT Validation (Pattern 1.3)

Section 5.0 states: "The `listOrders` resolver returns all objects when the `tenantId` filter is omitted or when it is supplied from the client without JWT-level validation." The schema exposes `listOrders(tenantId: ID, status: String)` — a client may supply an arbitrary `tenantId` value in the query argument. Since the resolver does not validate this against the authenticated user's JWT `tenantId`, a caller can substitute any `tenantId` to list all orders for a competing tenant.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `orderId` (NOTE: no user dimension in cache key)." If an order from `tenant-7a2b` is cached under its `orderId`, a subsequent request from `tenant-1ffe` for the same `orderId` receives the cached response, bypassing any future resolver-level tenant checks.

## Evidence

- **HAR trace**: JWT `x-tenant-id: tenant-1ffe` → `bulkOrderLookup(ids: ["O-2003", "O-1003", "O-3003"])` → HTTP 200 OK → response `tenantId: tenant-7a2b` with `sensitiveField` and `internalNotes`.
- **Section 4.0 (RISK-GQL-003)**: `getOrder` resolver lacks tenant check — documented known gap.
- **Section 4.0**: `bulkOrderLookup` lacks per-ID ownership filtering — documented gap.
- **Section 5.0**: `listOrders` accepts client-supplied `tenantId` without JWT validation.
- **Section 2.0**: Redis cache keyed by `orderId` only.

## Reproduction

**Step 1 — Attacker baseline:**

```graphql
query { getOrder(id: "O-1003") { orderId tenantId data { sensitiveField } } }
```

Expected: returns `tenantId: "tenant-1ffe"` — attacker's own order.

**Step 2 — Single cross-tenant lookup:**

```graphql
query { getOrder(id: "O-2003") { orderId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"getOrder": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-7a2b"` and order PII.

**Step 3 — Bulk cross-tenant lookup (primary HAR attack):**

```graphql
mutation { bulkOrderLookup(ids: ["O-2003", "O-1003", "O-3003"]) { orderId tenantId data { sensitiveField } } }
```

Expected secure outcome: only `tenant-1ffe` orders returned; foreign IDs filtered.  
Expected vulnerable outcome: HTTP 200 with orders from `tenant-7a2b` included.

**Step 4 — `listOrders` tenant override:**

```graphql
query { listOrders(tenantId: "tenant-7a2b") { orderId tenantId data { sensitiveField } } }
```

Expected secure outcome: results restricted to authenticated user's tenant despite the argument.  
Expected vulnerable outcome: full order list for `tenant-7a2b` returned.

## Remediation

- **Enforce `tenant_id` in `getOrder` resolver** (RISK-GQL-003): `WHERE orderId = $id AND tenant_id = $jwtTenantId`.
- **Filter `bulkOrderLookup` results post-fetch**: exclude any records where `tenant_id != jwtTenantId`.
- **Ignore client-supplied `tenantId` in `listOrders`**: always use `jwtTenantId` extracted from the JWT, never the query argument.
- **Add `tenantId` to Redis cache key**: change from `orderId` to `orderId:tenantId`.
- **Disable GraphQL introspection in production** to prevent enumeration of `sensitiveField` and internal field names.
