# Analysis Explanation

**System analysed:** ShopGrid Marketplace API — GQL-0053 (E-Commerce / Marketplace)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read §5.0** — Pattern 1.10 (cross-service identity propagation drift). Resolver does not re-validate caller identity per-object across the service boundary.
2. **Read §3.0** — Domain types: `Order`, `orderId`, `bulkOrderLookup`, `getOrder`.
3. **Read §4.0** — RISK-GQL-053 + bulk no per-ID filter. Cache by `orderId` only.
4. **Read HAR** — `bulkOrderLookup(ids: ["O-2053","O-1053","O-3053"])` from `tenant-b10d`. Response: `CONFIDENTIAL-b10d6b80`, `tenant-6b80`. `x-request-id: req-b10d6b80`.

## Consistency Guard
- Tenant IDs: `tenant-b10d`, `tenant-6b80`. Order IDs: `O-2053`, `O-1053`, `O-3053`. ownerId: `other-user-b10d6b80`. Leaked: `CONFIDENTIAL-b10d6b80`. Request ID: `req-b10d6b80`. All from this folder only.
