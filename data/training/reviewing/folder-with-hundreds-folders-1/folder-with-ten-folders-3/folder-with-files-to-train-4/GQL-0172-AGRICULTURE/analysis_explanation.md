# Analysis Explanation
**System analysed:** HarvestIQ IoT Platform — GQL-0172 (Agriculture / Precision Farming)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 7.1: `getResource` leaks operational IoT data cross-tenant.
2. HAR: `tenant-5ff5` queries `R-2172` → `tenant-41bd`: `CONFIDENTIAL-5ff541bd`, `req-5ff541bd`.
3. Agriculture IoT: soil sensors, crop projections, irrigation schedules — proprietary farming IP.

## Consistency Guard
Attacker: `tenant-5ff5`. Victim: `tenant-41bd`. Resource: `R-2172`. Sensitive: `CONFIDENTIAL-5ff541bd`. ownerId: `other-user-5ff541bd`. Request: `req-5ff541bd`. All from this folder only.
