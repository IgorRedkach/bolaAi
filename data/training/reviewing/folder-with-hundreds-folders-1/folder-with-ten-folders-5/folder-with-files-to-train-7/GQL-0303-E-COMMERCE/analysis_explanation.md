# Analysis Explanation
**Folder:** GQL-0303-E-COMMERCE | **Context source:** This folder's context.txt only.
- System: ShopGrid Marketplace API (GraphQL), E-Commerce/Marketplace
- Host: `api.shopgrid-marketplace.example.com`
- Attacker tenant: `tenant-b7ff`, victim tenant: `tenant-620e`
- HAR mutation: `updateOrder(id: "O-2303", input: {status: "approved", ownerId: "attacker-b7ff620e"})`, response key: `getOrder` — **INCONSISTENCY**: HAR uses `updateOrder` mutation but response key is `getOrder`. HAR operation is authoritative.
- Response: `ownerId: "other-user-b7ff620e"`, `sensitiveField: "CONFIDENTIAL-b7ff620e"`, `internalNotes: "Internal data exposed"` — cross-tenant data returned/modified
- Redis cache keyed by `orderId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-b7ff620e` is a response header (not a request header)
- Pattern 6.1: Schema/relationship over-exposure (Misconfiguration) — introspection enabled in production exposes internal types/fields; attacker leverages schema knowledge to craft unauthorized cross-tenant mutation; `updateOrder` resolver lacks tenancy check
- §4.0 RISK-GQL-303: `getOrder` resolver fetches by `orderId` only without `tenantId` cross-check; `bulkOrderLookup` also lacks per-ID ownership filtering
**Consistency Guard:** All values from this folder's context.txt only.
