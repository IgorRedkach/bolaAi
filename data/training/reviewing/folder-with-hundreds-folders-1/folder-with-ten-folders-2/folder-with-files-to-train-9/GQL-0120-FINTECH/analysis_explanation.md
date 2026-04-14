# Analysis Explanation
**System analysed:** PayBridge Transaction API — GQL-0120 (FinTech / Payments)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.12 (mass assignment via object fields). Client supplies `ownerId` in mutation input.
2. HAR: `updateResource(id: "R-2120", input: {status: "approved", ownerId: "attacker-47dfd116"})` from `tenant-47df`. Response `tenant-d116`: `CONFIDENTIAL-47dfd116`. `x-request-id: req-47dfd116`.

## Consistency Guard
Tenant IDs: `tenant-47df`, `tenant-d116`. Resource: `R-2120`. Attacker ownerId: `attacker-47dfd116`. Leaked: `CONFIDENTIAL-47dfd116`. Request: `req-47dfd116`. All from this folder only.
