# Analysis Explanation
**System analysed:** FirstResponse CAD Integration — GQL-0208 (Government / Emergency Services)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-208: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.12: BOLA — mass assignment via object fields; privileged response fields not scoped to tenant.
3. HAR: `tenant-ba72` queries `getResource(id: "R-2208")` → `tenant-d92d` CAD dispatch record: `CONFIDENTIAL-ba72d92d`, `req-ba72d92d`.
4. Government CAD domain: dispatch records, unit locations, emergency call data — first responder and public security risk.

## Consistency Guard
Attacker: `tenant-ba72`. Victim: `tenant-d92d`. Resource: `R-2208`. Sensitive: `CONFIDENTIAL-ba72d92d`. ownerId: `other-user-ba72d92d`. Request: `req-ba72d92d`. All from this folder only.
