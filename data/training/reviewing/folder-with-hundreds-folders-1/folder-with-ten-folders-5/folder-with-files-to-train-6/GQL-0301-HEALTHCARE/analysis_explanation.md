# Analysis Explanation
**Folder:** GQL-0301-HEALTHCARE | **Context source:** This folder's context.txt only.
- System: PatientCore EHR API, Healthcare/EHR Platform
- Host: `api.patientcore-ehr-api.example.com`
- Attacker tenant: `tenant-e63d`, victim tenant: `tenant-67c9`
- HAR request: `listPatients(tenantId: "tenant-67c9")` — client injects foreign tenantId
- **Inconsistency in context.txt:** Request uses `listPatients` but response JSON key is `getPatient`. HAR is authoritative.
- Response: `ownerId: other-user-e63d67c9`, `sensitiveField: CONFIDENTIAL-e63d67c9`
- `x-request-id: req-e63d67c9` is a server-assigned response header, not a request header
- Redis keyed by `patientId` only — no tenant dimension (§2.0 cache note)
- HIPAA PHI breach: EHR patient data exposed across tenant boundaries
- Pattern 5.1: Authorization-bypass injection — client-supplied `tenantId` injected into query bypasses authorization boundary
**Consistency Guard:** All values from this folder's context.txt only.
