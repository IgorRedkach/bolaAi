# Analysis Explanation
**System analysed:** SpectreNet Policy Control — GQL-0065 (Telecom / 5G Core)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 10.2 (parameter escalation / own session scope extension — single-user).
2. §4.0 RISK-GQL-065: `getResource` fetches by `resourceId` only — no tenantId match.
3. Domain types: `Resource`, `resourceId`, `updateResource`, `bulkResourceLookup` (from schema §3.0 and HAR).
4. HAR: `updateResource(id: "R-2065", input: {status: "approved", ownerId: "attacker-6611eb0a"})` from `tenant-6611`. Response `tenant-eb0a`: `CONFIDENTIAL-6611eb0a`. `x-request-id: req-6611eb0a`.
5. Key observation: `ownerId` is provided in mutation `input` — this is a mass-assignment vector. Attacker escalates scope by injecting ownership field into a cross-tenant mutation.

## Consistency Guard
Tenant IDs: `tenant-6611`, `tenant-eb0a`. Resource: `R-2065`. Attacker ownerId injected: `attacker-6611eb0a`. Leaked: `CONFIDENTIAL-6611eb0a`. Request: `req-6611eb0a`. All from this folder only.
