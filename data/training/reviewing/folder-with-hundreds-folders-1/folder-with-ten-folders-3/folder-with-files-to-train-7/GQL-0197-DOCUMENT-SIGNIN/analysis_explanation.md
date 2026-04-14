# Analysis Explanation
**System analysed:** SignFlow eSign Platform — GQL-0197 (Document Signing / Legal Tech)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-197: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 10.2: Single-User — parameter escalation/own session scope extension via `ownerId` in mutation input.
3. HAR: `tenant-a2c8` submits `updateResource(id: "R-2197", input: {ownerId: "attacker-a2c89a21"})` → `tenant-9a21` signing document: `CONFIDENTIAL-a2c89a21`, `req-a2c89a21`.
4. Document Signing domain: legal documents, contracts — contract fraud and compliance violation.

## Consistency Guard
Attacker: `tenant-a2c8`. Victim: `tenant-9a21`. Resource: `R-2197`. Sensitive: `CONFIDENTIAL-a2c89a21`. ownerId input: `attacker-a2c89a21`. Request: `req-a2c89a21`. All from this folder only.
