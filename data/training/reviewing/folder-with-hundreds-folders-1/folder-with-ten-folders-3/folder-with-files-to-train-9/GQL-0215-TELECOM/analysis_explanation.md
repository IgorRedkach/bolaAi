# Analysis Explanation
**System analysed:** SpectreNet Policy Control — GQL-0215 (Telecom / Policy Control)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-215: `getResource` resolver fetches by `resourceId` only, no `tenantId` check.
2. §5.0 Pattern 6.1: Misconfiguration — schema/relationship over-exposure; `ownerId` in mutation input, `tenantId`/`sensitiveField` in response.
3. HAR: `tenant-e7ea` submits `updateResource(id: "R-2215", input: {ownerId: "attacker-e7ea0912"})` → `tenant-0912` policy data: `CONFIDENTIAL-e7ea0912`, `req-e7ea0912`.
4. Telecom domain: network policy configs, subscriber data — service disruption and privacy violation.

## Consistency Guard
Attacker: `tenant-e7ea`. Victim: `tenant-0912`. Resource: `R-2215`. Sensitive: `CONFIDENTIAL-e7ea0912`. ownerId input: `attacker-e7ea0912`. Request: `req-e7ea0912`. All from this folder only.
