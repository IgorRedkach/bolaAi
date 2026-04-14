# Analysis Explanation
**System analysed:** HarvestIQ IoT Platform — GQL-0122 (Agriculture / Precision Farming)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-122: `getResource` fetches by `resourceId` only, enabling Pattern 3.1 (client-assumed authority).
2. HAR: `tenant-f0d1` mutates `R-2122` with `ownerId: "attacker-f0d17852"` → `tenant-7852` data: `CONFIDENTIAL-f0d17852`, `req-f0d17852`.
3. Agriculture/IoT: soil sensors, irrigation controls — crop safety and farm infrastructure risk.

## Consistency Guard
Attacker: `tenant-f0d1`. Victim: `tenant-7852`. Resource: `R-2122`. Sensitive: `CONFIDENTIAL-f0d17852`. ownerId input: `attacker-f0d17852`. Request: `req-f0d17852`. All from this folder only.
