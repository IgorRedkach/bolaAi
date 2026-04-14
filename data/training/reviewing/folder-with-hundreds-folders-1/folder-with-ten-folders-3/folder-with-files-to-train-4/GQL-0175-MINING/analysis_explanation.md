# Analysis Explanation
**System analysed:** OreTrack Fleet Management — GQL-0175 (Mining / Resource Extraction)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 10.2: `updateResource` parameter escalation — ownerId in input bypasses session scope.
2. HAR: `tenant-ff68` mutates `R-2175` with `ownerId: "attacker-ff68b089"` → `tenant-b089`: `CONFIDENTIAL-ff68b089`, `req-ff68b089`.
3. Mining: fleet telemetry, equipment safety — operational sabotage risk.

## Consistency Guard
Attacker: `tenant-ff68`. Victim: `tenant-b089`. Resource: `R-2175`. Sensitive: `CONFIDENTIAL-ff68b089`. ownerId input: `attacker-ff68b089`. Request: `req-ff68b089`. All from this folder only.
