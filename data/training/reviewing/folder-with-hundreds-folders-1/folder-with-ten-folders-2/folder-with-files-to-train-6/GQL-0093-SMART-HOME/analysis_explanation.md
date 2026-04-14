# Analysis Explanation
**System analysed:** NeoBuild BAS Platform — GQL-0093 (Smart Home / Building Automation)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 1.6 (write operations without ownership check — BOLA). Mutation can modify cross-tenant BAS records.
2. HAR: `updateResource(id: "R-2093", input: {status: "approved", ownerId: "attacker-082e3aaa"})` from `tenant-082e`. Response `tenant-3aaa`: `CONFIDENTIAL-082e3aaa`. `x-request-id: req-082e3aaa`.
3. Physical security context: BAS write operations have physical safety implications (HVAC, access control, security systems).

## Consistency Guard
Tenant IDs: `tenant-082e`, `tenant-3aaa`. Resource: `R-2093`. Attacker ownerId: `attacker-082e3aaa`. Leaked: `CONFIDENTIAL-082e3aaa`. Request: `req-082e3aaa`. All from this folder only.
