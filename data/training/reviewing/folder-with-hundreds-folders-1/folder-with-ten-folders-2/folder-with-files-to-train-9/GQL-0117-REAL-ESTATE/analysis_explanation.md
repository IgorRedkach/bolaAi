# Analysis Explanation
**System analysed:** EstateFlow Property API — GQL-0117 (Real Estate / PropTech)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.8 (predictable/sequential IDs). Bulk lookup with predictable IDs enables cross-tenant enumeration.
2. HAR: `bulkResourceLookup(["R-2117","R-1117","R-3117"])` from `tenant-73a5`. Response `tenant-6e21`: `CONFIDENTIAL-73a56e21`. `x-request-id: req-73a56e21`.

## Consistency Guard
Tenant IDs: `tenant-73a5`, `tenant-6e21`. Resources: `R-2117`, `R-1117`, `R-3117`. ownerId: `other-user-73a56e21`. Leaked: `CONFIDENTIAL-73a56e21`. Request: `req-73a56e21`. All from this folder only.
