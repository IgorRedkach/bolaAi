# Analysis Explanation
**System analysed:** PatientCore EHR API — GQL-0201 (Healthcare / Electronic Health Records)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-201: `getPatient` resolver fetches by `patientId` only, no `tenantId` ownership check.
2. §5.0 Pattern 1.3: BOLA — bulk/list endpoints allow cross-tenant patient record access.
3. HAR: `tenant-6112` submits `updatePatient(id: "P-2201", input: {ownerId: "attacker-6112876b"})` → `tenant-876b` patient record: `CONFIDENTIAL-6112876b`, `req-6112876b`.
4. Healthcare EHR domain: patient records — HIPAA violation, direct patient safety implications.

## Consistency Guard
Attacker: `tenant-6112`. Victim: `tenant-876b`. Patient: `P-2201`. Sensitive: `CONFIDENTIAL-6112876b`. ownerId input: `attacker-6112876b`. Request: `req-6112876b`. All from this folder only.
