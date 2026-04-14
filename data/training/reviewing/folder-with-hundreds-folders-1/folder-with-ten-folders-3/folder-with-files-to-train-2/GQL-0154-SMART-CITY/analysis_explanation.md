# Analysis Explanation
**System analysed:** MetroPulse Traffic Orchestration — GQL-0154 (Smart City / Traffic Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.5: `getIntersection` fetches by `nodeId` without ownership check — draft config access.
2. HAR: `tenant-3963` queries `I-2154` → `tenant-24ec` traffic data: `CONFIDENTIAL-396324ec`, `req-396324ec`.
3. Smart City: signal timing, traffic control draft configs — public safety and infrastructure risk.

## Consistency Guard
Attacker: `tenant-3963`. Victim: `tenant-24ec`. Resource: `I-2154`. Sensitive: `CONFIDENTIAL-396324ec`. ownerId: `other-user-396324ec`. Request: `req-396324ec`. All from this folder only.
