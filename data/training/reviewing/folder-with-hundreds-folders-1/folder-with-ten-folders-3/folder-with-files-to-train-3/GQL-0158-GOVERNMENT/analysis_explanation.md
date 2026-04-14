# Analysis Explanation
**System analysed:** FirstResponse CAD Integration — GQL-0158 (Government / Public Safety)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.5: `updateResource` no tenancy guard — multi-tenant BOLA.
2. HAR: `tenant-e26b` mutates `R-2158` with `ownerId: "attacker-e26b30e4"` → `tenant-30e4`: `CONFIDENTIAL-e26b30e4`, `req-e26b30e4`.
3. Government/Public Safety: CAD dispatch data — emergency responder safety risk.

## Consistency Guard
Attacker: `tenant-e26b`. Victim: `tenant-30e4`. Resource: `R-2158`. Sensitive: `CONFIDENTIAL-e26b30e4`. ownerId input: `attacker-e26b30e4`. Request: `req-e26b30e4`. All from this folder only.
