# Analysis Explanation
**System analysed:** HarvestIQ IoT Platform — GQL-0222 (Agriculture / Precision Farming IoT)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-222: `getResource`/`listResources` resolver lacks `tenantId` check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 1.2: BOLA — related/linked IoT sensor nodes traversed without tenant ownership verification.
3. HAR: `tenant-497c` queries `listResources(tenantId: "tenant-2ba9")` → `tenant-2ba9` farm sensor data: `CONFIDENTIAL-497c2ba9`, `req-497c2ba9`.
4. Agriculture domain: sensor data, crop yields, irrigation configs — agricultural espionage.

## Consistency Guard
Attacker: `tenant-497c`. Victim: `tenant-2ba9`. Resource: `R-2222`. Sensitive: `CONFIDENTIAL-497c2ba9`. ownerId: `other-user-497c2ba9`. Request: `req-497c2ba9`. All from this folder only.
