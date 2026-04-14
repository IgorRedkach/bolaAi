# Analysis Explanation
**System analysed:** PatientCore EHR API — GQL-0151 (Healthcare / EHR Platform)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §5.0 Pattern 9.1: Single GraphQL endpoint, no per-op tenant isolation — cross-tenant `getPatient`.
2. HAR: `tenant-e124` queries `P-2151` → `tenant-f7a1` PHI: `CONFIDENTIAL-e124f7a1`, `req-e124f7a1`.
3. Healthcare/EHR: diagnoses, medications, clinical history — HIPAA violation, patient safety risk.

## Consistency Guard
Attacker: `tenant-e124`. Victim: `tenant-f7a1`. Resource: `P-2151`. Sensitive: `CONFIDENTIAL-e124f7a1`. ownerId: `other-user-e124f7a1`. Request: `req-e124f7a1`. All from this folder only.
