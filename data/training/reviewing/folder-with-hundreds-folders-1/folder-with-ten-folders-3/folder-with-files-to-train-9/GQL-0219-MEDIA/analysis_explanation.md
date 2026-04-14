# Analysis Explanation
**System analysed:** StreamCore VOD Platform — GQL-0219 (Media / Video-on-Demand)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-219: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 10.2: Single-User — parameter escalation/own session scope extension via `ownerId` in mutation input.
3. HAR: `tenant-d2d3` submits `updateResource(id: "R-2219", input: {ownerId: "attacker-d2d33c91"})` → `tenant-3c91` VOD content: `CONFIDENTIAL-d2d33c91`, `req-d2d33c91`.
4. Media/VOD domain: content rights, DRM configs, subscriber data — copyright and privacy violation.

## Consistency Guard
Attacker: `tenant-d2d3`. Victim: `tenant-3c91`. Resource: `R-2219`. Sensitive: `CONFIDENTIAL-d2d33c91`. ownerId input: `attacker-d2d33c91`. Request: `req-d2d33c91`. All from this folder only.
