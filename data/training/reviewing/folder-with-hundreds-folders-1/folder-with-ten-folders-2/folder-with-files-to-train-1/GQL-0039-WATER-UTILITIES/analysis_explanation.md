# Analysis Explanation

**System analysed:** AquaGrid Meter Management — GQL-0039 (Water Utilities / Smart Meters)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 6.1 (Schema/relationship over-exposure). Explicit: "GraphQL introspection is enabled in production. The schema exposes internal type names, field descriptions, and sensitive relationship paths that aid exploitation." — introspection is legitimately in scope for this example.
2. **Read Section 3.0 schema** — Confirmed field names: `sensitiveField`, `internalNotes`, `auditLog`, `items`, `getResource`, `bulkResourceLookup`. These are exactly what introspection would reveal.
3. **Read Section 4.0** — RISK-GQL-039: resolver does not cross-check `tenantId`. `bulkResourceLookup` has no per-ID filter.
4. **Read HAR** — Attacker (`tenant-6943`) sent `getResource(id: "R-2039")` with specific cross-tenant ID. Response `200 OK` returned `tenantId: "tenant-d463"`, `sensitiveField: "CONFIDENTIAL-6943d463"`, `internalNotes: "Internal data exposed"`. `x-request-id: req-6943d463`.
5. **Introspection is grounded** — Unlike other examples where introspection was speculative, §5.0 explicitly confirms it is enabled. Step 1 in reproduction is therefore legitimate and not conditional.
6. **Attack chain** — Introspection (Finding 1) supplies field names → `getResource(id: "R-2039")` (Finding 2, HAR) uses those field names → bulk enumeration (Finding 3, §4.0 note) scales the attack.

## Consistency Guard
- All tenant IDs (`tenant-6943`, `tenant-d463`), resource IDs (`R-2039`), ownerId (`other-user-6943d463`), leaked values (`CONFIDENTIAL-6943d463`), request IDs (`req-6943d463`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.
