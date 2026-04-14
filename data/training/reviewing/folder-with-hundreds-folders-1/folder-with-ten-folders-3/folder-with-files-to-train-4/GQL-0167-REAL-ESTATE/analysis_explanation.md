# Analysis Explanation
**System analysed:** EstateFlow Property API — GQL-0167 (Real Estate / PropTech)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 3.3: `getResource` semantically over-broad — cross-tenant property access.
2. HAR: `tenant-c3be` queries `R-2167` → `tenant-f8a4`: `CONFIDENTIAL-c3bef8a4`, `req-c3bef8a4`.
3. PropTech: property valuations, lease agreements, client financials.

## Consistency Guard
Attacker: `tenant-c3be`. Victim: `tenant-f8a4`. Resource: `R-2167`. Sensitive: `CONFIDENTIAL-c3bef8a4`. ownerId: `other-user-c3bef8a4`. Request: `req-c3bef8a4`. All from this folder only.
