# Expected Response

## System
- Domain: Healthcare / EHR Platform
- System: PatientCore EHR API
- Example ID: GQL-0151

## Priority Findings

### Finding 1: Healthcare EHR — Single Endpoint GraphQL Exposes Cross-Tenant Patient Records (Pattern 9.1)
**Severity:** Critical
**Category:** GraphQL Platform / Single Endpoint Vulnerability

**Summary:**
Per §5.0 (Pattern 9.1 — GraphQL single endpoint vulnerabilities): The unified GraphQL endpoint does not enforce per-operation tenant isolation, enabling cross-tenant patient data access. An attacker from `tenant-e124` queried `getPatient(id: "P-2151")` and received EHR patient data belonging to `tenant-f7a1`, including `CONFIDENTIAL-e124f7a1`. In Healthcare / EHR, this constitutes unauthorized access to Protected Health Information (PHI), violating HIPAA and exposing diagnoses, medications, and clinical history.

**Evidence from HAR:**
- Request: `POST https://api.patientcore-ehr-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-e124`
- Query: `getPatient(id: "P-2151") { patientId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`: `tenantId: "tenant-f7a1"`, `ownerId: "other-user-e124f7a1"`, `sensitiveField: "CONFIDENTIAL-e124f7a1"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e124f7a1`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 9.1 | Single endpoint, no per-op tenant guard |
| HAR request | x-tenant-id | Attacker tenant-e124 |
| HAR response | tenantId | Cross-tenant PHI tenant-f7a1 |
| HAR response | sensitiveField | CONFIDENTIAL-e124f7a1 |

## Steps to Reproduce

### Step 1 — getPatient cross-tenant EHR (HAR)
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e124" \
  -d '{"query": "query { getPatient(id: \"P-2151\") { patientId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** `tenant-f7a1` EHR PHI returned. **Secure:** FORBIDDEN.

## Remediation
1. Per-operation tenant guard middleware on the single endpoint.
2. `getPatient` resolver: `WHERE patient_id=$id AND tenant_id=$jwt.tenantId`.
3. PHI fields encrypted at rest; all access audit logged.
4. Redis cache key: `patient:{tenantId}:{patientId}`.
