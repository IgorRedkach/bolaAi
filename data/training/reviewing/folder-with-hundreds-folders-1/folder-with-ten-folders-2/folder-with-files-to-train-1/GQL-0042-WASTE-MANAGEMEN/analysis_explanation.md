# Analysis Explanation

**System analysed:** CleanRoute IoT Platform — GQL-0042 (Waste Management / Smart Bins)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 10.1 (ID swap in own request / Single-User). Key: "A single authenticated user substitutes their own valid `resourceId` with a victim's `resourceId`. With one token, data belonging to another user is accessible." This is the minimal-privilege attacker model — no account takeover required.
2. **Read Section 3.0 schema** — `bulkResourceLookup(ids: [ID!]!)` and `getResource(id: ID!)` confirmed. Same generic Resource/ResourceData types.
3. **Read Section 4.0** — RISK-GQL-042: resolver does not verify `tenantId`. `bulkResourceLookup` has no per-ID filter.
4. **Read HAR** — `bulkResourceLookup(ids: ["R-2042", "R-1042", "R-3042"])` from `tenant-db28`. Response `200 OK` returned `tenant-2d3c` data: `CONFIDENTIAL-db282d3c`, `internalNotes: "Internal data exposed"`. `x-request-id: req-db282d3c`.
5. **Pattern 10.1 interpretation** — The "ID swap in own request" perfectly describes the bulk lookup: the attacker mixes own IDs with victim IDs in a single array. The single JWT is sufficient — no escalation needed.
6. **Added Step 3** — `getResource(id: "R-2042")` as single-ID swap variant; grounded in §4.0 and the HAR's cross-tenant resource ID.

## Consistency Guard
- All tenant IDs (`tenant-db28`, `tenant-2d3c`), resource IDs (`R-2042`, `R-1042`, `R-3042`), ownerId (`other-user-db282d3c`), leaked values (`CONFIDENTIAL-db282d3c`), request IDs (`req-db282d3c`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.
