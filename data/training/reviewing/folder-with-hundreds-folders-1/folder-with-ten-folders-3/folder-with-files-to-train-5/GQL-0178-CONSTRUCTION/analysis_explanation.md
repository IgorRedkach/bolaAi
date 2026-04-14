# Analysis Explanation
**System analysed:** BuildCore BIM Collaboration — GQL-0178 (Construction / BIM Collaboration)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-178: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.2: BOLA — related/linked resources traversed without ownership verification.
3. HAR: `tenant-a80d` submits `updateResource(id: "R-2178", input: {ownerId: "attacker-a80d8609"})` → `tenant-8609` BIM record: `CONFIDENTIAL-a80d8609`, `req-a80d8609`.
4. Construction domain: BIM models contain structural and regulatory data — unauthorized mutation risks safety compliance.

## Consistency Guard
Attacker: `tenant-a80d`. Victim: `tenant-8609`. Resource: `R-2178`. Sensitive: `CONFIDENTIAL-a80d8609`. ownerId input: `attacker-a80d8609`. Request: `req-a80d8609`. All from this folder only.
