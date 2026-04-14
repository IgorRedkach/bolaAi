## Analysis reasoning

I reviewed the ShopGrid Marketplace API v5.0.7 architecture specification, GraphQL schema, and HAR trace.

1. **Primary attack vector is bulk lookup**: the HAR request shows `bulkOrderLookup(ids: ["O-2003", "O-1003", "O-3003"])` from `tenant-1ffe`. Section 4.0 documents this gap explicitly. The response confirms cross-tenant data return (`tenantId: tenant-7a2b`), proving the mutation processes IDs without tenant ownership filtering.

2. **`listOrders` is a distinct, more dangerous secondary vector**: section 5.0 specifically calls out the `listOrders` resolver returning all objects when `tenantId` is omitted or supplied by the client without JWT validation. This is distinct from bulk lookup — it is a list endpoint where the client controls the scope filter. An attacker does not need to enumerate individual IDs; they simply supply a competitor's `tenantId` to receive their entire order catalog, purchase history, and associated PII.

3. **Three attack paths confirmed or documented**: (a) single `getOrder` — RISK-GQL-003 explicit; (b) `bulkOrderLookup` — section 4.0 explicit and HAR confirmed; (c) `listOrders` — section 5.0 explicit client-controlled filter. Each path must be independently remediated.

4. **Redis cache adds amplification risk**: cache keyed by `orderId` only means that even if resolvers are patched, stale cross-tenant data may persist in cache for any TTL period. This must be fixed alongside the resolver logic.

5. **E-commerce context**: order data in a marketplace includes purchasing patterns, product selection, pricing, and customer PII. Cross-tenant access to competitor order data could enable price undercutting, customer poaching, or supply chain intelligence gathering.
