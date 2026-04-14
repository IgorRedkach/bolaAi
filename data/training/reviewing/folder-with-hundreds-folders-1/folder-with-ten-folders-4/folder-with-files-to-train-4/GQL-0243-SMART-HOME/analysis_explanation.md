# Analysis Explanation
**System analysed:** NeoBuild BAS Platform — GQL-0243 (Smart Home / Building Automation)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-243: `bulkResourceLookup` lacks per-ID `tenantId` check.
2. §5.0 Pattern 1.1: BOLA — ID in path without ownership check; resource IDs are directly usable as access keys.
3. HAR: `tenant-b167` calls `bulkResourceLookup(ids: ["R-2243","R-1243","R-3243"])` → `tenant-39a0` BAS data: `CONFIDENTIAL-b16739a0`, `req-b16739a0`.
4. Smart Home/BAS domain: HVAC configs, access control states, sensor data — physical security implications.

## Consistency Guard
Attacker: `tenant-b167`. Victim: `tenant-39a0`. Resources: `R-2243`, `R-1243`, `R-3243`. Sensitive: `CONFIDENTIAL-b16739a0`. ownerId: `other-user-b16739a0`. Request: `req-b16739a0`. All from this folder only.
