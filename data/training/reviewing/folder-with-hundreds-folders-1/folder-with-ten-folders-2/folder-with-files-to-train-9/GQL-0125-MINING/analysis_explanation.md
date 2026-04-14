# Analysis Explanation
**System analysed:** OreTrack Fleet Management — GQL-0125 (Mining / Resource Extraction)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-125 + §5.0 Pattern 5.1: `updateResource` accepts unsanitized `ownerId` in input, enabling authorization-bypass injection.
2. HAR: `tenant-5198` mutates `R-2125` with `ownerId: "attacker-5198d2ed"` → `tenant-d2ed` data: `CONFIDENTIAL-5198d2ed`, `req-5198d2ed`.
3. Mining: fleet telemetry, equipment state — safety and extraction ops integrity at risk.

## Consistency Guard
Attacker: `tenant-5198`. Victim: `tenant-d2ed`. Resource: `R-2125`. Sensitive: `CONFIDENTIAL-5198d2ed`. ownerId input: `attacker-5198d2ed`. Request: `req-5198d2ed`. All from this folder only.
