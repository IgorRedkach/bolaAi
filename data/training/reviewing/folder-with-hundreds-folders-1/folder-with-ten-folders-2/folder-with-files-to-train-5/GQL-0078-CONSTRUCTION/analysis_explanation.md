# Analysis Explanation
**System analysed:** BuildCore BIM Collaboration — GQL-0078 (Construction / BIM)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 3.1 (client-assumed authority — insecure design). Server trusts client-supplied IDs without verifying ownership server-side.
2. HAR: `bulkResourceLookup(["R-2078","R-1078","R-3078"])` from `tenant-0c67`. Response `tenant-1b85`: `CONFIDENTIAL-0c671b85`. `x-request-id: req-0c671b85`.
3. Pattern 3.1 angle: design flaw — the API was designed assuming clients only send their own IDs, without an enforcement mechanism.

## Consistency Guard
Tenant IDs: `tenant-0c67`, `tenant-1b85`. Resources: `R-2078`, `R-1078`, `R-3078`. ownerId: `other-user-0c671b85`. Leaked: `CONFIDENTIAL-0c671b85`. Request: `req-0c671b85`. All from this folder only.
