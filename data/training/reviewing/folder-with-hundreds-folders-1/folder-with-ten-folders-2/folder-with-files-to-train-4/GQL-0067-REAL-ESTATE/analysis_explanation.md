# Analysis Explanation
**System analysed:** EstateFlow Property API — GQL-0067 (Real Estate / PropTech)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.1 (ID in path without ownership check). Attacker substitutes resourceId.
2. §4.0 RISK-GQL-067: `getResource` fetches by `resourceId` only — no tenantId match.
3. HAR: `getResource(id: "R-2067")` from `tenant-43da`. Response `tenant-efd6`: `CONFIDENTIAL-43daefd6`. `x-request-id: req-43daefd6`.
4. Pattern 1.1 angle: direct ID substitution (not bulk, not nested) — simplest BOLA variant.

## Consistency Guard
Tenant IDs: `tenant-43da`, `tenant-efd6`. Resource: `R-2067`. ownerId: `other-user-43daefd6`. Leaked: `CONFIDENTIAL-43daefd6`. Request: `req-43daefd6`. All from this folder only.
