# Analysis Explanation
**System analysed:** TrialVault ClinicalOps API — GQL-0221 (Pharmaceutical / Clinical Operations)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-221: `getResource` resolver fetches by `resourceId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.1: BOLA — ID in path without ownership check.
3. HAR: `tenant-dc47` submits `updateResource(id: "R-2221", input: {ownerId: "attacker-dc47c541"})` → `tenant-c541` clinical trial data: `CONFIDENTIAL-dc47c541`, `req-dc47c541`.
4. Pharmaceutical domain: clinical trial data, patient enrollment, trial results — GCP/FDA 21 CFR Part 11 violation.

## Consistency Guard
Attacker: `tenant-dc47`. Victim: `tenant-c541`. Resource: `R-2221`. Sensitive: `CONFIDENTIAL-dc47c541`. ownerId input: `attacker-dc47c541`. Request: `req-dc47c541`. All from this folder only.
