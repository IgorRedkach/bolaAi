# Analysis Explanation
**System analysed:** ManuControl Robotics Fleet — GQL-0157 (Industrial IoT / Manufacturing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.3: `listResources` accepts client `tenantId` — bulk list BOLA.
2. HAR: `tenant-227f` passes `tenantId: "tenant-6031"` → `CONFIDENTIAL-227f6031`, `req-227f6031`.
3. Industrial IoT: robot controls, production metrics — manufacturing IP and safety risk.

## Consistency Guard
Attacker: `tenant-227f`. Victim: `tenant-6031`. Sensitive: `CONFIDENTIAL-227f6031`. ownerId: `other-user-227f6031`. Request: `req-227f6031`. All from this folder only.
