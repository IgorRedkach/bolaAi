# Analysis Explanation
**System analysed:** AeroOps Flight Management — GQL-0187 (Aviation / Flight Operations)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-187: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 2.2: BAC — metadata/attribute side-channel; mutation response leaks cross-tenant ownership attributes.
3. HAR: `tenant-84bf` submits `updateResource(id: "R-2187", input: {ownerId: "attacker-84bf62b1"})` → `tenant-62b1` flight record: `CONFIDENTIAL-84bf62b1`, `req-84bf62b1`.
4. Aviation domain: flight schedules, operational logs, crew data — aviation security and safety incident.

## Consistency Guard
Attacker: `tenant-84bf`. Victim: `tenant-62b1`. Resource: `R-2187`. Sensitive: `CONFIDENTIAL-84bf62b1`. ownerId input: `attacker-84bf62b1`. Request: `req-84bf62b1`. All from this folder only.
