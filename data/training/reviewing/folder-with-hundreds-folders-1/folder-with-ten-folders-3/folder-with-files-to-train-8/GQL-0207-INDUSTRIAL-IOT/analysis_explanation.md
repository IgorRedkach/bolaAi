# Analysis Explanation
**System analysed:** ManuControl Robotics Fleet — GQL-0207 (Industrial IoT / Robotics Fleet)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-207: `getResource`/`listResources` resolver lacks `tenantId` check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 1.10: BOLA — cross-service identity propagation drift; `tenantId` not re-validated downstream.
3. HAR: `tenant-441c` queries `listResources(tenantId: "tenant-ffb6")` → `tenant-ffb6` robotics data: `CONFIDENTIAL-441cffb6`, `req-441cffb6`.
4. Industrial IoT domain: robot telemetry, control params, operational schedules — industrial espionage and physical harm risk.

## Consistency Guard
Attacker: `tenant-441c`. Victim: `tenant-ffb6`. Resource: `R-2207`. Sensitive: `CONFIDENTIAL-441cffb6`. ownerId: `other-user-441cffb6`. Request: `req-441cffb6`. All from this folder only.
