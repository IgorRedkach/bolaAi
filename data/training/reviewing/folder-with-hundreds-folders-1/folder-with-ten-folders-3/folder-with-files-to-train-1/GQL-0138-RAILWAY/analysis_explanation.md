# Analysis Explanation
**System analysed:** RailCore Operations API — GQL-0138 (Railway / SCADA)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.7: `listResources` accepts client tenantId; parent resource authorization not checked for nested resources.
2. HAR: `tenant-4648` passes `tenantId: "tenant-105c"` → `CONFIDENTIAL-4648105c`, `req-4648105c`.
3. Railway/SCADA: signal controls, track scheduling — critical infrastructure safety.

## Consistency Guard
Attacker: `tenant-4648`. Victim: `tenant-105c`. Sensitive: `CONFIDENTIAL-4648105c`. ownerId: `other-user-4648105c`. Request: `req-4648105c`. All from this folder only.
