# Analysis Explanation
**System analysed:** ManuControl Robotics Fleet — GQL-0057 (Industrial IoT / Manufacturing)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 3.3 (semantic ambiguity / over-broad endpoints). Resolver does not scope response to caller's tenant.
2. HAR: `getResource(id: "R-2057")` from `tenant-4cfd`. Response `tenant-da11`: `CONFIDENTIAL-4cfdda11`. `x-request-id: req-4cfdda11`.
3. §4.0 RISK-GQL-057 + bulkResourceLookup no filter.

## Consistency Guard
Tenant IDs: `tenant-4cfd`, `tenant-da11`. Resource: `R-2057`. ownerId: `other-user-4cfdda11`. Leaked: `CONFIDENTIAL-4cfdda11`. Request: `req-4cfdda11`. All from this folder only.
