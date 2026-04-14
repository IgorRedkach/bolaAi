# Analysis Explanation
**System analysed:** PowerGrid Customer Billing API — GQL-0164 (Energy / Utilities / Smart Grid)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 1.12: `updateMeter` accepts `ownerId` in input — mass assignment BOLA.
2. HAR: `tenant-180b` mutates `M-2164` with `ownerId: "attacker-180bccb6"` → `tenant-ccb6`: `CONFIDENTIAL-180bccb6`, `req-180bccb6`.
3. Energy/Smart Grid: meter config, billing records — utility fraud and grid disruption.

## Consistency Guard
Attacker: `tenant-180b`. Victim: `tenant-ccb6`. Resource: `M-2164`. Sensitive: `CONFIDENTIAL-180bccb6`. ownerId input: `attacker-180bccb6`. Request: `req-180bccb6`. All from this folder only.
