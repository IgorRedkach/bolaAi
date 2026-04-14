# Analysis Explanation
**System analysed:** WingTech Maintenance Portal — GQL-0226 (Aerospace / MRO)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-226: `updateResource` resolver fetches by `resourceId` only — no `tenantId` ownership check.
2. §5.0 Pattern 1.7: BOLA — nested resource mutation without parent authorization.
3. HAR: `tenant-216f` issues `updateResource(id: "R-2226", input: {status: "approved", ownerId: "attacker-216f2e67"})` → response returns `tenant-2e67` data: `CONFIDENTIAL-216f2e67`, `req-216f2e67`.
4. Aerospace/MRO domain: maintenance records, flight-critical data — cross-tenant write in aviation is a safety and espionage risk.
5. Attacker also supplies `ownerId` in mutation input, attempting to hijack ownership — server accepts it without validation.

## Consistency Guard
Attacker: `tenant-216f`. Victim: `tenant-2e67`. Resource: `R-2226`. Sensitive: `CONFIDENTIAL-216f2e67`. ownerId: `other-user-216f2e67`. Request: `req-216f2e67`. All from this folder only.
