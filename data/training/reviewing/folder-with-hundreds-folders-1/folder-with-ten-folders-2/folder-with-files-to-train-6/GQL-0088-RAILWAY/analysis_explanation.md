# Analysis Explanation
**System analysed:** RailCore Operations API — GQL-0088 (Railway)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 10.5 (draft/non-published resource access — single-user). Records not yet published are accessible cross-tenant.
2. HAR: `getResource(id: "R-2088")` from `tenant-c8a2`. Response `tenant-3271`: `CONFIDENTIAL-c8a23271`. `x-request-id: req-c8a23271`.
3. Railway safety context: draft timetables/signalling records accessed before authorization = safety risk.

## Consistency Guard
Tenant IDs: `tenant-c8a2`, `tenant-3271`. Resource: `R-2088`. ownerId: `other-user-c8a23271`. Leaked: `CONFIDENTIAL-c8a23271`. Request: `req-c8a23271`. All from this folder only.
