# Analysis Explanation
**System analysed:** ParkIQ Management API — GQL-0100 (Parking / Smart Mobility)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 3.1 (client-assumed authority — insecure design). Server accepts client-supplied ID without ownership verification.
2. HAR: `updateIntersection(id: "I-2100", input: {status: "approved", ownerId: "attacker-76ca59c0"})` from `tenant-76ca`. Response `getIntersection` from `tenant-59c0`: `CONFIDENTIAL-76ca59c0`. `x-request-id: req-76ca59c0`.
3. Domain-specific: objects are `Intersection`/`nodeId` (not generic Resource). Resolver is `updateIntersection`/`getIntersection`. All from HAR response body.

## Consistency Guard
Tenant IDs: `tenant-76ca`, `tenant-59c0`. Intersection: `I-2100`. Attacker ownerId: `attacker-76ca59c0`. Leaked: `CONFIDENTIAL-76ca59c0`. Request: `req-76ca59c0`. All from this folder only.
