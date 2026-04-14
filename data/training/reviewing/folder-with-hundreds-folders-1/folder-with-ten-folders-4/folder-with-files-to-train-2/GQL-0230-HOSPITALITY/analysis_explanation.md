# Analysis Explanation
**System analysed:** StayPro Property API — GQL-0230 (Hospitality / Hotel PMS)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-230: `getResource` resolver fetches by `resourceId` only — no `tenantId` ownership check.
2. §5.0 Pattern 1.12: Mass assignment via object fields — client's GraphQL selection set controls which fields are returned; no server-side field-level authorization.
3. HAR: `tenant-a23f` queries `getResource(id: "R-2230")` with full field selection → `tenant-5bb4` data: `CONFIDENTIAL-a23f5bb4`, `req-a23f5bb4`.
4. Hospitality/Hotel PMS domain: guest PII, room assignments, rate agreements — cross-tenant data breach in PMS systems can expose hospitality operators to GDPR/PCI violations.

## Consistency Guard
Attacker: `tenant-a23f`. Victim: `tenant-5bb4`. Resource: `R-2230`. Sensitive: `CONFIDENTIAL-a23f5bb4`. ownerId: `other-user-a23f5bb4`. Request: `req-a23f5bb4`. All from this folder only.
