# Analysis Explanation
**System analysed:** RewardCore Loyalty API — GQL-0123 (Retail / Loyalty Programme)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-123 + §5.0 Pattern 3.3: `listResources` accepts client-supplied `tenantId`; over-broad endpoint design.
2. HAR: `tenant-69ae` queries `tenantId: "tenant-e99d"` → `CONFIDENTIAL-69aee99d`, `req-69aee99d`.
3. Retail/Loyalty: customer points balances, redemption history — consumer PII.

## Consistency Guard
Attacker: `tenant-69ae`. Victim: `tenant-e99d`. Sensitive: `CONFIDENTIAL-69aee99d`. ownerId: `other-user-69aee99d`. Request: `req-69aee99d`. All from this folder only.
