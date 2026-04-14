# Analysis Explanation
**System analysed:** RewardCore Loyalty API — GQL-0173 (Retail / Loyalty Programme)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 9.1: Single GraphQL endpoint, no per-op tenant isolation.
2. HAR: `tenant-d49b` queries `R-2173, R-1173, R-3173` → `tenant-6f52`: `CONFIDENTIAL-d49b6f52`, `req-d49b6f52`.
3. Retail/Loyalty: points balances, promotional data — consumer PII.

## Consistency Guard
Attacker: `tenant-d49b`. Victim: `tenant-6f52`. Resources: `R-2173, R-1173, R-3173`. Sensitive: `CONFIDENTIAL-d49b6f52`. ownerId: `other-user-d49b6f52`. Request: `req-d49b6f52`. All from this folder only.
