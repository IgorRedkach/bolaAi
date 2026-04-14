# Analysis Explanation
**System analysed:** CleanRoute IoT Platform — GQL-0142 (Waste Management / Smart Bins)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.12: `listResources` accepts `tenantId` object field — mass assignment BOLA.
2. HAR: `tenant-c02c` passes `tenantId: "tenant-c39f"` → `CONFIDENTIAL-c02cc39f`, `req-c02cc39f`.
3. Waste Management/IoT: bin schedules, route data — smart city infrastructure.

## Consistency Guard
Attacker: `tenant-c02c`. Victim: `tenant-c39f`. Sensitive: `CONFIDENTIAL-c02cc39f`. ownerId: `other-user-c02cc39f`. Request: `req-c02cc39f`. All from this folder only.
