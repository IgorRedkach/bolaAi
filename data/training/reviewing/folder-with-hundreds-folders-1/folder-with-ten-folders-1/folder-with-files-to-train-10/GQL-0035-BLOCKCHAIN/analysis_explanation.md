# Analysis Explanation

**System analysed:** ChainVault DeFi API — GQL-0035 (Blockchain / DeFi)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 3.3 (Semantic ambiguity / over-broad endpoints). The `listResources` endpoint design allows any `tenantId` to be passed as a query filter, creating an over-broad scope that conflates query parameter with identity.
2. **Read Section 3.0 schema** — Confirmed `listResources(tenantId: ID, status: String)` accepts `tenantId` from the caller. The schema design exposes the tenant filter as a public input.
3. **Read Section 4.0** — RISK-GQL-035: resolver does not cross-check `tenantId` against JWT. Also confirmed `bulkResourceLookup` has no per-ID ownership filtering.
4. **Read HAR** — Attacker (`tenant-3c88`) sent `listResources(tenantId: "tenant-d89f")`. Response `200 OK` returned `sensitiveField: "CONFIDENTIAL-3c88d89f"`, `internalNotes: "Internal data exposed"` from `tenant-d89f`. `x-request-id: req-3c88d89f` logged.
5. **Grounded pattern 3.3 definition** — The `listResources` query signature is the semantic gap: it allows any `tenantId` input rather than scoping to the JWT's authenticated identity. This is the "over-broad endpoint" characteristic.
6. **Bulk enumeration** — Documented from §4.0 (not HAR-grounded; §4.0 explicitly states the gap).
7. **Redis cache risk** — §2.0: cache keyed by `resourceId` only; added remediation.

## Consistency Guard
- All tenant IDs (`tenant-3c88`, `tenant-d89f`), leaked values (`CONFIDENTIAL-3c88d89f`, `other-user-3c88d89f`), and request IDs (`req-3c88d89f`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.
