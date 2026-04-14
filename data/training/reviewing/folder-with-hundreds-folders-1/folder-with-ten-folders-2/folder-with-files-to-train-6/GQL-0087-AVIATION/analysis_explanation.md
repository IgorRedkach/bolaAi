# Analysis Explanation
**System analysed:** AeroOps Flight Management — GQL-0087 (Aviation)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 10.2 (parameter escalation/own session scope extension). Single authenticated user extends scope to victim's records.
2. HAR: `updateResource(id: "R-2087", input: {status: "approved", ownerId: "attacker-5a2cce7e"})` from `tenant-5a2c`. Response `tenant-ce7e`: `CONFIDENTIAL-5a2cce7e`. `x-request-id: req-5a2cce7e`.
3. Aviation safety: unauthorized mutation of flight status/maintenance records has regulatory and safety implications.

## Consistency Guard
Tenant IDs: `tenant-5a2c`, `tenant-ce7e`. Resource: `R-2087`. Attacker ownerId: `attacker-5a2cce7e`. Leaked: `CONFIDENTIAL-5a2cce7e`. Request: `req-5a2cce7e`. All from this folder only.
