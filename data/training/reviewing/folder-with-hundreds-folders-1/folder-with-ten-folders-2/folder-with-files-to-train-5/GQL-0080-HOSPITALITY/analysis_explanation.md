# Analysis Explanation
**System analysed:** StayPro Property API — GQL-0080 (Hospitality / Property Management)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 4.2 (persistence poisoning via lifecycle actions — integrity). Lifecycle state change (status: "approved") used as vector to poison stored ownership.
2. HAR: `updateResource(id: "R-2080", input: {status: "approved", ownerId: "attacker-4952c719"})` from `tenant-4952`. Response `tenant-c719`: `CONFIDENTIAL-4952c719`. `x-request-id: req-4952c719`.
3. Pattern 4.2 distinguishes from simple BOLA: the attack persists in the database — `ownerId` is mutated, affecting future reads. Step 2 (verify persistence) demonstrates this.

## Consistency Guard
Tenant IDs: `tenant-4952`, `tenant-c719`. Resource: `R-2080`. Attacker ownerId injected: `attacker-4952c719`. Leaked: `CONFIDENTIAL-4952c719`. Request: `req-4952c719`. All from this folder only.
