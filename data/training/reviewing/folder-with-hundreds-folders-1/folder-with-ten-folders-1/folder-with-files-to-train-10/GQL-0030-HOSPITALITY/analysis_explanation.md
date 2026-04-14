# Analysis Explanation

**System analysed:** StayPro Property API — GQL-0030 (Hospitality / Hotel PMS)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 1.9 (batch/bulk endpoints). The `bulkResourceLookup` mutation accepts arbitrary IDs without per-ID ownership checks.

2. **Read Section 3.0 GraphQL schema** — identified `listResources(tenantId: ID, status: String)` — the `tenantId` parameter is client-supplied.

3. **Read HAR** — the primary operation is `listResources(tenantId: "tenant-ab6e")`. The attacker (`x-tenant-id: tenant-3271`) passed the victim's `tenantId` as a query argument. Response confirmed `tenantId: "tenant-ab6e"` data returned.

4. **Key distinction from prior GQL examples** — the attack vector here is not a single-resource ID substitution but a full-tenant listing via a client-controlled `tenantId` argument in `listResources`. The HAR shows this specific vector.

5. **Removed unsupported steps** (introspection, "if" qualifiers).

## Consistency Guard
- All tenant IDs (`tenant-3271`, `tenant-ab6e`), field values, and endpoint URLs drawn from this folder's context.txt only.
