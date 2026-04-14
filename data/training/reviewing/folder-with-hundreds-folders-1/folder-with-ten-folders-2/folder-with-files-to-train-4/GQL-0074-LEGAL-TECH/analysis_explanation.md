# Analysis Explanation
**System analysed:** LexVault eDiscovery API — GQL-0074 (Legal Tech / eDiscovery)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.9 (batch/bulk lookup endpoints — BOLA). Both `getResource` and `bulkResourceLookup` lack per-ID ownership checks.
2. §4.0 RISK-GQL-074: `getResource` fetches by ID only — no tenantId match.
3. HAR: `getResource(id: "R-2074")` from `tenant-8ea4`. Response `tenant-6926`: `CONFIDENTIAL-8ea46926`. `x-request-id: req-8ea46926`.
4. Domain impact: attorney-client privilege breach — legal data has stronger confidentiality requirements than typical business data.

## Consistency Guard
Tenant IDs: `tenant-8ea4`, `tenant-6926`. Resource: `R-2074`. ownerId: `other-user-8ea46926`. Leaked: `CONFIDENTIAL-8ea46926`. Request: `req-8ea46926`. All from this folder only.
