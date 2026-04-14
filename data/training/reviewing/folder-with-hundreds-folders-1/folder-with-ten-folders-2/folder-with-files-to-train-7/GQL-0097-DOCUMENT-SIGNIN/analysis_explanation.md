# Analysis Explanation
**System analysed:** SignFlow eSign Platform — GQL-0097 (Document Signing / eSign)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.10 (cross-service identity propagation drift). Downstream resolver trusts forwarded identity.
2. HAR: `getResource(id: "R-2097")` from `tenant-e074`. Response `tenant-fbad`: `CONFIDENTIAL-e074fbad`. `x-request-id: req-e074fbad`.
3. eSign domain: legally binding document exposure — contract validity and legal liability implications.

## Consistency Guard
Tenant IDs: `tenant-e074`, `tenant-fbad`. Resource: `R-2097`. ownerId: `other-user-e074fbad`. Leaked: `CONFIDENTIAL-e074fbad`. Request: `req-e074fbad`. All from this folder only.
