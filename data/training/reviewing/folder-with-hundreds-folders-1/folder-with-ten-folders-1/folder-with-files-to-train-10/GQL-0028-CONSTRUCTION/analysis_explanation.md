# Analysis Explanation

**System analysed:** BuildCore BIM Collaboration — GQL-0028 (Construction / BIM Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 1.7 (nested resources without parent authorization). The resolver does not enforce ownership or tenancy on nested resource access.

2. **Read Section 4.0** — RISK-GQL-028: `getResource` fetches by `resourceId` only. `bulkResourceLookup` accepts arbitrary IDs without ownership filter.

3. **Read the HAR trace** — the primary operation in the HAR is `bulkResourceLookup(ids: ["R-2028", "R-1028", "R-3028"])`, not `getResource`. Attacker `tenant-0301` sent a bulk request including cross-tenant resource `R-2028`. Response confirmed `tenantId: "tenant-11f3"` — cross-tenant access.

4. **Corrected Step 2** — the existing expected_response.md used a single `getResource` query for Step 2, but the HAR evidence shows `bulkResourceLookup`. Updated to reflect the actual HAR operation as the primary evidence.

5. **Removed unsupported steps** — introspection step removed (not in context), "if" qualifiers removed.

## Consistency Guard
- No data from any other training example was used.
- All tenant IDs (`tenant-0301`, `tenant-11f3`), resource IDs (`R-2028`, `R-1028`, `R-3028`), and field values are drawn directly from this folder's context.txt.
