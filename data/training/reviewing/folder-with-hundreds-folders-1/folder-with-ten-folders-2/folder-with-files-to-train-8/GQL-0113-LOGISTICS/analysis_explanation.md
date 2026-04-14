# Analysis Explanation
**System analysed:** FreightLens Tracking API — GQL-0113 (Logistics / Supply Chain)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.3: `bulkShipmentLookup` accepts arbitrary IDs, enabling bulk BOLA.
2. HAR: `tenant-6b23` mutates `S-2113` with `ownerId: "attacker-6b23551e"` → `tenant-551e` data: `CONFIDENTIAL-6b23551e`, `req-6b23551e`.
3. Logistics: shipping manifests, freight route data — competitive supply chain intelligence.

## Consistency Guard
Attacker: `tenant-6b23`. Victim: `tenant-551e`. Resource: `S-2113`. Sensitive: `CONFIDENTIAL-6b23551e`. ownerId input: `attacker-6b23551e`. Request: `req-6b23551e`. All from this folder only.
