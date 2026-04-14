# Analysis Explanation
**System analysed:** EstateFlow Property API — GQL-0217 (Real Estate / Property Marketplace)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-217: `getResource`/`listResources` resolver lacks `tenantId` check; accepts caller-supplied `tenantId`.
2. §5.0 Pattern 9.1: GraphQL Platform — single endpoint vulnerability; no per-operation tenant isolation middleware.
3. HAR: `tenant-c805` queries `listResources(tenantId: "tenant-e10d")` → `tenant-e10d` property data: `CONFIDENTIAL-c805e10d`, `req-c805e10d`.
4. Real Estate domain: property portfolios, valuations, client data — business and privacy breach.

## Consistency Guard
Attacker: `tenant-c805`. Victim: `tenant-e10d`. Resource: `R-2217`. Sensitive: `CONFIDENTIAL-c805e10d`. ownerId: `other-user-c805e10d`. Request: `req-c805e10d`. All from this folder only.
