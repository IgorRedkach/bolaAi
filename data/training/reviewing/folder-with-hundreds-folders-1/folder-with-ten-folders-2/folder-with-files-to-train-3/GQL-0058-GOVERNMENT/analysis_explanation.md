# Analysis Explanation
**System analysed:** FirstResponse CAD Integration — GQL-0058 (Government / Public Safety)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 4.2 (persistence poisoning). Lifecycle mutations (`updateResource`, `deleteResource`) share the same tenant gap as read operations.
2. HAR: `getResource(id: "R-2058")` from `tenant-285d`. Response `tenant-5b48`: `CONFIDENTIAL-285d5b48`. `x-request-id: req-285d5b48`.
3. §4.0 RISK-GQL-058 confirms resolver gap and bulk no filter.
4. Step 2 (persistence poisoning): uses `status: "cancelled"` on a CAD dispatch record — grounded in §3.0 `updateResource` + §5.0 Pattern 4.2 explicitly naming lifecycle actions.

## Consistency Guard
Tenant IDs: `tenant-285d`, `tenant-5b48`. Resource: `R-2058`. ownerId: `other-user-285d5b48`. Leaked: `CONFIDENTIAL-285d5b48`. Request: `req-285d5b48`. All from this folder only.
