# Analysis Explanation
**System analysed:** LexVault eDiscovery API — GQL-0224 (Legal Tech / eDiscovery)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-224: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.5: BOLA — multi-tenant/cross-tenant access via mutation without tenant validation.
3. HAR: `tenant-64ed` submits `updateResource(id: "R-2224", input: {ownerId: "attacker-64ed2db6"})` → `tenant-2db6` legal document: `CONFIDENTIAL-64ed2db6`, `req-64ed2db6`.
4. Legal Tech domain: case documents, privileged comms, litigation data — attorney-client privilege and legal confidentiality violation.

## Consistency Guard
Attacker: `tenant-64ed`. Victim: `tenant-2db6`. Resource: `R-2224`. Sensitive: `CONFIDENTIAL-64ed2db6`. ownerId input: `attacker-64ed2db6`. Request: `req-64ed2db6`. All from this folder only.
