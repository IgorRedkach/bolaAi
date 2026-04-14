# Analysis Explanation
**System analysed:** RewardCore Loyalty API — GQL-0223 (Retail / Loyalty Program)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-223: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.3: BOLA — bulk/list endpoint returns cross-tenant loyalty records.
3. HAR: `tenant-46c2` queries `getResource(id: "R-2223")` → `tenant-3fa0` loyalty data: `CONFIDENTIAL-46c23fa0`, `req-46c23fa0`.
4. Retail domain: member profiles, points balances, redemption histories — loyalty fraud and PII exposure.

## Consistency Guard
Attacker: `tenant-46c2`. Victim: `tenant-3fa0`. Resource: `R-2223`. Sensitive: `CONFIDENTIAL-46c23fa0`. ownerId: `other-user-46c23fa0`. Request: `req-46c23fa0`. All from this folder only.
