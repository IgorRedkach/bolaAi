# Analysis Explanation
**System analysed:** GrantFlow CRM API — GQL-0177 (Non-Profit / Grant Management)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-177: `getResource` resolver fetches by `resourceId` only, no `tenantId` check.
2. §5.0 Pattern 1.1: BOLA — ID in path without ownership check.
3. HAR: `tenant-e221` queries `getResource(id: "R-2177")` → `tenant-5ba7` grant record: `CONFIDENTIAL-e2215ba7`, `req-e2215ba7`.
4. Non-profit domain: grant applications and donor/beneficiary data — privacy violation and compliance breach.

## Consistency Guard
Attacker: `tenant-e221`. Victim: `tenant-5ba7`. Resource: `R-2177`. Sensitive: `CONFIDENTIAL-e2215ba7`. ownerId: `other-user-e2215ba7`. Request: `req-e2215ba7`. All from this folder only.
