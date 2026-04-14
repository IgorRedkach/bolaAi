# Analysis Explanation
**System analysed:** VenueCore Ticketing API — GQL-0199 (Event Management / Ticketing)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-199: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.1: BOLA — ID in path without ownership check.
3. HAR: `tenant-25a5` submits `updateResource(id: "R-2199", input: {ownerId: "attacker-25a56193"})` → `tenant-6193` ticketing record: `CONFIDENTIAL-25a56193`, `req-25a56193`.
4. Event Management domain: ticket data, event configs, venue records — ticket fraud and event disruption.

## Consistency Guard
Attacker: `tenant-25a5`. Victim: `tenant-6193`. Resource: `R-2199`. Sensitive: `CONFIDENTIAL-25a56193`. ownerId input: `attacker-25a56193`. Request: `req-25a56193`. All from this folder only.
