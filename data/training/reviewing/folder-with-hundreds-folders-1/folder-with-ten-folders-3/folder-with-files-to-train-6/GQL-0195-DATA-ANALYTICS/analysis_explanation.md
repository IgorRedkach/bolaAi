# Analysis Explanation
**System analysed:** InsightGraph Analytics API — GQL-0195 (Data Analytics / Business Intelligence)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-195: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 9.1: GraphQL Platform — single endpoint vulnerability; no per-operation tenant isolation.
3. HAR: `tenant-3333` queries `getResource(id: "R-2195")` → `tenant-06eb` analytics record: `CONFIDENTIAL-333306eb`, `req-333306eb`.
4. Data Analytics domain: dashboards, query results, data pipelines — competitive intelligence and data sovereignty breach.

## Consistency Guard
Attacker: `tenant-3333`. Victim: `tenant-06eb`. Resource: `R-2195`. Sensitive: `CONFIDENTIAL-333306eb`. ownerId: `other-user-333306eb`. Request: `req-333306eb`. All from this folder only.
