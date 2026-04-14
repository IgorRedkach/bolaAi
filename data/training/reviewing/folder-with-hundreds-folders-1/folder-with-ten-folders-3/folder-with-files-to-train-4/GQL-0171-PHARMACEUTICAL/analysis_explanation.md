# Analysis Explanation
**System analysed:** TrialVault ClinicalOps API — GQL-0171 (Pharmaceutical / Clinical Trials)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 6.1: Schema over-exposes clinical relationship fields — bulk cross-tenant access.
2. HAR: `tenant-350d` queries `R-2171, R-1171, R-3171` → `tenant-c13c`: `CONFIDENTIAL-350dc13c`, `req-350dc13c`.
3. Pharma/Clinical: adverse events, FDA submissions, trial protocols — regulatory and patient safety risk.

## Consistency Guard
Attacker: `tenant-350d`. Victim: `tenant-c13c`. Resources: `R-2171, R-1171, R-3171`. Sensitive: `CONFIDENTIAL-350dc13c`. ownerId: `other-user-350dc13c`. Request: `req-350dc13c`. All from this folder only.
