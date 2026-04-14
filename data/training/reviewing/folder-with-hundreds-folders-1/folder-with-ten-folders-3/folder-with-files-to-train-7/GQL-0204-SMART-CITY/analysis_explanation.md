# Analysis Explanation
**System analysed:** MetroPulse Traffic Orchestration — GQL-0204 (Smart City / Traffic Orchestration)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-204: `getIntersection`/`listIntersections` resolver lacks `tenantId` parent ownership check.
2. §5.0 Pattern 1.7: BOLA — nested resource (intersection) without parent traffic zone authorization.
3. HAR: `tenant-dd41` queries `listIntersections(tenantId: "tenant-3801")` → `tenant-3801` intersection records: `CONFIDENTIAL-dd413801`, `req-dd413801`.
4. Smart City domain: intersection configurations, signal states — traffic manipulation and public safety incidents.

## Consistency Guard
Attacker: `tenant-dd41`. Victim: `tenant-3801`. Intersection: `I-2204`. Sensitive: `CONFIDENTIAL-dd413801`. ownerId: `other-user-dd413801`. Request: `req-dd413801`. All from this folder only.
