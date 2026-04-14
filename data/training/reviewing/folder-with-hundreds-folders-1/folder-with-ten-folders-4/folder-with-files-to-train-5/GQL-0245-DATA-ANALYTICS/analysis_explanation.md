# Analysis Explanation
**System analysed:** InsightGraph Analytics API — GQL-0245 (Data Analytics / BI Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-245: `getResource` lacks `tenantId` ownership check.
2. §5.0 Pattern 1.3: BOLA — bulk/list endpoint; resolver serves as list gateway, cross-tenant enumerable.
3. HAR: `tenant-a1eb` queries `getResource(id: "R-2245")` → `tenant-6690` BI data: `CONFIDENTIAL-a1eb6690`, `req-a1eb6690`.
4. Data Analytics/BI domain: reports, dashboards, business metrics — trade secrets, financial projections.

## Consistency Guard
Attacker: `tenant-a1eb`. Victim: `tenant-6690`. Resource: `R-2245`. Sensitive: `CONFIDENTIAL-a1eb6690`. ownerId: `other-user-a1eb6690`. Request: `req-a1eb6690`. All from this folder only.
