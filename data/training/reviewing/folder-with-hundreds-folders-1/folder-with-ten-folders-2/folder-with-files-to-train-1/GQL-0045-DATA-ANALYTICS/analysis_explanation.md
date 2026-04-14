# Analysis Explanation

**System analysed:** InsightGraph Analytics API — GQL-0045 (Data Analytics / BI Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method

1. **Read Section 5.0** — Pattern 1.1 (ID in path/query without ownership check). §5.0 explicitly names: "An attacker with a valid `tenant-e491` token can substitute any `resourceId` value to retrieve objects belonging to `tenant-d637`." This provides exact tenant IDs grounding the findings.
2. **Read Section 3.0 schema** — `getResource(id: ID!)` and `updateResource(id: ID!, input: ResourceInput!)` confirmed. The `ResourceInput` accepts `ownerId` (confirmed by HAR).
3. **Read Section 4.0** — RISK-GQL-045: resolver does not verify `tenantId`. `bulkResourceLookup` has no per-ID filter.
4. **Read HAR** — Attack is `updateResource(id: "R-2045", input: {status: "approved", ownerId: "attacker-e491d637"})`. Response `200 OK`, `tenant-d637` data returned: `CONFIDENTIAL-e491d637`. `x-request-id: req-e491d637`. Timing: wait 65 ms.
5. **§5.0 explicit tenants used** — Since §5.0 explicitly names `tenant-e491` and `tenant-d637`, all findings reference these exact values without any inference needed.
6. **Added Step 2 (read first)** — Pattern 1.1 classically describes read-first BOLA via `getResource`. The HAR demonstrates a write escalation; both are documented — read via Step 2, write via Step 3 (HAR).

## Consistency Guard
- All tenant IDs (`tenant-e491`, `tenant-d637`), resource IDs (`R-2045`), injected ownerId (`attacker-e491d637`), leaked values (`CONFIDENTIAL-e491d637`, `other-user-e491d637`), request IDs (`req-e491d637`) drawn from this folder's context.txt only.
- JWT token segment used verbatim from HAR entry.
