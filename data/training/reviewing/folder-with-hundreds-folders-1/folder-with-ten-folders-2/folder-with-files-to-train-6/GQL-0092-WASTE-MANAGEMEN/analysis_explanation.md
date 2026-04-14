# Analysis Explanation
**System analysed:** CleanRoute IoT Platform — GQL-0092 (Waste Management / IoT)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.5 (multi-tenant/cross-tenant access). API trusts client-supplied `tenantId` over JWT.
2. HAR: `bulkResourceLookup(["R-2092","R-1092","R-3092"])` from `tenant-f6b3`. Response `tenant-c668`: `CONFIDENTIAL-f6b3c668`. `x-request-id: req-f6b3c668`.
3. Pattern 1.5: client passes victim tenantId directly — both bulk and list endpoints vulnerable.

## Consistency Guard
Tenant IDs: `tenant-f6b3`, `tenant-c668`. Resources: `R-2092`, `R-1092`, `R-3092`. ownerId: `other-user-f6b3c668`. Leaked: `CONFIDENTIAL-f6b3c668`. Request: `req-f6b3c668`. All from this folder only.
