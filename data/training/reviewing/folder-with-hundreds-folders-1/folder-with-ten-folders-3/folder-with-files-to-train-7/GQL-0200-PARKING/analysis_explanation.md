# Analysis Explanation
**System analysed:** ParkIQ Management API — GQL-0200 (Parking / Smart City Infrastructure)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-200: `getIntersection` resolver fetches by `id` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.2: BOLA — related/linked resources; intersection node accessed without parent tenant authorization.
3. HAR: `tenant-1226` submits `updateIntersection(id: "I-2200", input: {ownerId: "attacker-12267bb3"})` → `tenant-7bb3` intersection: `CONFIDENTIAL-12267bb3`, `req-12267bb3`.
4. Smart Parking domain: intersection nodes, traffic signal sync — public safety impact.

## Consistency Guard
Attacker: `tenant-1226`. Victim: `tenant-7bb3`. Intersection: `I-2200`. Sensitive: `CONFIDENTIAL-12267bb3`. ownerId input: `attacker-12267bb3`. Request: `req-12267bb3`. All from this folder only.
