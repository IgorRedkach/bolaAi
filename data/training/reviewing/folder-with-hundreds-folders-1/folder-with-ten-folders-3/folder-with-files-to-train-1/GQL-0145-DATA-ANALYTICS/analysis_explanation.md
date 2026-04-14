# Analysis Explanation
**System analysed:** InsightGraph Analytics API — GQL-0145 (Data Analytics / BI Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 3.3: `getResource` semantically over-broad — no resource-type scoping, no tenancy.
2. HAR: `tenant-536b` queries `R-2145` → `tenant-af2c` data: `CONFIDENTIAL-536baf2c`, `req-536baf2c`.
3. BI Platform: business intelligence reports, customer analytics — proprietary data exfiltration.

## Consistency Guard
Attacker: `tenant-536b`. Victim: `tenant-af2c`. Resource: `R-2145`. Sensitive: `CONFIDENTIAL-536baf2c`. ownerId: `other-user-536baf2c`. Request: `req-536baf2c`. All from this folder only.
