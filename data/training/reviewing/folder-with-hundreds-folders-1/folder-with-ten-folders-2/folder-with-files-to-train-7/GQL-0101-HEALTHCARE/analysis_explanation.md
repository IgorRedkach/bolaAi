# Analysis Explanation
**System analysed:** PatientCore EHR API — GQL-0101 (Healthcare / EHR)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 3.3 (semantic ambiguity/over-broad endpoints). `getPatient` implies own-patient context but accepts any patient ID.
2. HAR: `getPatient(id: "P-2101")` from `tenant-eaeb`. Response `getPatient` from `tenant-9964`: `CONFIDENTIAL-eaeb9964`. `x-request-id: req-eaeb9964`.
3. Domain: `Patient`/`patientId`/`getPatient` — confirmed by HAR response body. HIPAA PHI breach.
4. HTTP 404 (not 403) recommended: in EHR context, confirming patient ID existence is itself a PHI disclosure.

## Consistency Guard
Tenant IDs: `tenant-eaeb`, `tenant-9964`. Patient: `P-2101`. ownerId: `other-user-eaeb9964`. Leaked: `CONFIDENTIAL-eaeb9964`. Request: `req-eaeb9964`. All from this folder only.
