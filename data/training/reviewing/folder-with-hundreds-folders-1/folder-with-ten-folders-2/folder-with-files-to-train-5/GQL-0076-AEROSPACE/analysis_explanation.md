# Analysis Explanation
**System analysed:** WingTech Maintenance Portal — GQL-0076 (Aerospace / MRO)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.12 (mass assignment via object fields). Client-supplied fields accepted in mutation input without restriction.
2. HAR: `listResources(tenantId: "tenant-1559")` from `tenant-c9ed`. Response `tenant-1559`: `CONFIDENTIAL-c9ed1559`. `x-request-id: req-c9ed1559`.
3. Pattern 1.12 angle: both `listResources` (read) and `updateResource` mutation (write) are vectors — input schema accepts `ownerId`/`tenantId`.

## Consistency Guard
Tenant IDs: `tenant-c9ed`, `tenant-1559`. ownerId: `other-user-c9ed1559`. Leaked: `CONFIDENTIAL-c9ed1559`. Request: `req-c9ed1559`. All from this folder only.
