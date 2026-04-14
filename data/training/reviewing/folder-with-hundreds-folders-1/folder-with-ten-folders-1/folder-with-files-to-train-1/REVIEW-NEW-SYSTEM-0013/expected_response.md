# Expected Response

## System
- **Name:** CareSphere FHIR Integration Gateway
- **Domain:** Healthcare / EMR / Telehealth Interoperability
- **Document version analysed:** 9.0.3 (FINAL) + implementation doc 4.2.0
- **Regulatory scope:** HIPAA / ePHI — findings here carry patient safety and legal implications

---

## Priority Findings

### Finding 1 — Shadow API: Deprecated `/api/v1/` Endpoint Bypasses SMART on FHIR Security Controls (Pattern 4.3 — Integrity downgrade via versioning)
**Severity:** Critical / ePHI Exposure
**Affected endpoint:** `GET https://api.caresphere.health/api/v1/export/patients/{id}/clinical-notes`
**Referenced in context:** Section 2.3 (Node.js Legacy Gateway), Section 4.0 (RISK-EPHI-099), HAR response header

**Summary:**
The architecture (Section 2.3) documents that the legacy Node.js gateway (`/api/v1/`) was officially sunset in 2024 (Epic: HLTH-404) but was never physically decommissioned because two hospital networks refused to migrate. The current Apigee WAF rules only protect `/fhir/v4/*` paths. The routing infrastructure still silently forwards all `/api/v1/*` requests to the legacy unmonitored cluster.

**Evidence from HAR:**
- Request URL path: `/api/v1/export/patients/pt_10001/clinical-notes` — this path is not in any published OpenAPI spec
- Response header: `x-legacy-router: v1-node-cluster-deprecated` — the request was served by the deprecated legacy Node.js cluster, confirming the shadow API is reachable
- Response status: `200 OK` — the legacy cluster did not reject the unauthenticated-scope request

---

### Finding 2 — BOLA: Patient ID Substitution on Clinical Notes Export (Pattern 1.1 — ID in path without ownership check)
**Severity:** Critical / ePHI Disclosure
**Affected endpoint:** `GET https://api.caresphere.health/api/v1/export/patients/{patient_id}/clinical-notes`
**Referenced in context:** Section 4.0 (Pattern 1.1), Section 6.0 (Node.js handler), HAR trace

**Summary:**
The Node.js handler (Section 6.0, lines 121–128) extracts `requestedPatientId` from the URL path parameter (`req.params.patient_id`) and queries the database directly with it. The code explicitly documents the missing check:
```javascript
// The code FAILS to enforce the boundary: if (requestedPatientId !== tokenPatientId) { throw 403 }
// It blindly trusts the URI parameter over the secure JWT claim.
```

The attacker's JWT (`sub: pt_88192`) belongs to Patient A with restricted scope `patient/Observation.read`. By substituting victim Patient B's ID (`pt_10001`) in the URL, the attacker receives `pt_10001`'s complete clinical history.

**Evidence from HAR:**
- Request JWT decoded payload: `{"sub":"pt_88192","scopes":["patient/Observation.read"]}` — attacker is `pt_88192`
- Request URL: `/api/v1/export/patients/pt_10001/clinical-notes` — target is `pt_10001` (mismatch confirmed)
- Response body: `"export_target": "pt_10001"` — server confirms it returned `pt_10001`'s records to an attacker with `sub: pt_88192`
- Response body: `"total_records": 42` — 42 clinical notes returned
- Response scope violation: the JWT scope `patient/Observation.read` (lab results / vitals) was ignored; the endpoint returned full clinical narrative notes

---

### Finding 3 — Unrestricted ePHI Disclosure: Psychiatric and Oncology Records Not Filtered (Section 4.0 Pattern 2.1 — Functional pivot / data filtering bypass)
**Severity:** Critical / Highly Sensitive ePHI (Psychiatric records)
**Affected endpoint:** `GET https://api.caresphere.health/api/v1/export/patients/{patient_id}/clinical-notes`
**Referenced in context:** Section 5.2 (legacy schema), Section 6.0 (SQL query), HAR response body

**Summary:**
The modern FHIR gateway (Section 5.1) strips records with `meta.security` tags `PSY` (Psychiatry) and `R` (Restricted) unless a `break-glass` scope is present. The legacy Node.js handler (Section 6.0) executes:
```sql
SELECT note_id, encounter_date, department, raw_clinical_text
FROM clinical_notes_archive
WHERE patient_id = $1
ORDER BY encounter_date DESC
```
There is no filter on `department`, `is_restricted`, or any sensitivity label. The comment confirms this is the flaw: `"It fails to append: AND department != 'PSYCHIATRY' AND is_restricted = FALSE"`.

**Evidence from HAR response body:**
- `doc-99182`: `department: "PSYCHIATRY"`, `is_restricted: true` — contains raw psychiatric assessment including diagnoses and medication information
- `doc-88114`: `department: "ONCOLOGY"`, `is_restricted: true` — contains cancer biopsy results
- Response `content.size: 5120480` (~5.1 MB) — anomalous bulk export from a mobile pedometer app (`user-agent: PedometerPlus/1.0.4`)

---

## Evidence Map

| Artifact location | Finding 1 (Shadow API) | Finding 2 (Patient ID BOLA) | Finding 3 (Unfiltered ePHI) |
|---|---|---|---|
| Section 2.3 | Legacy v1 gateway not decommissioned | — | — |
| Section 4.0 (RISK-EPHI-099) | WAF only protects `/fhir/v4/*` | BOLA — no patient ID check in v1 | No PSY filter in v1 |
| Section 6.0 code | — | `requestedPatientId` used without verifying `!== tokenPatientId` | SQL has no `department` / `is_restricted` filter |
| HAR response header | `x-legacy-router: v1-node-cluster-deprecated` | — | — |
| HAR request URL | Path is `/api/v1/` not `/fhir/v4/` | Sub `pt_88192` requests `pt_10001` | — |
| HAR response body | `200 OK` | `export_target: pt_10001`, 42 records | PSYCHIATRY + ONCOLOGY restricted records in plaintext |
| HAR content.size | — | — | 5.1 MB — anomalous for mobile app |

---

## Steps to Reproduce

### Finding 1 + Finding 2 — Shadow API + Patient ID BOLA (combined in one probe)

**Step 1 — Establish attacker's own baseline (legitimate access)**
```
GET https://api.caresphere.health/api/v1/export/patients/pt_88192/clinical-notes
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwdF84ODE5MiIsInNjb3BlcyI6WyJwYXRpZW50L09ic2VydmF0aW9uLnJlYWQiXX0...
Accept: application/json
```
Expected baseline: `200 OK` returning `pt_88192`'s own records. This confirms the shadow API is reachable with a restricted-scope token.

**Step 2 — Substitute victim patient ID (exact HAR replay)**
```
GET https://api.caresphere.health/api/v1/export/patients/pt_10001/clinical-notes
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwdF84ODE5MiIsInNjb3BlcyI6WyJwYXRpZW50L09ic2VydmF0aW9uLnJlYWQiXX0...
Accept: application/json
User-Agent: PedometerPlus/1.0.4 (iOS 17.1)
```
**Vulnerable outcome (confirmed by HAR):**
- `200 OK`
- Response header includes `x-legacy-router: v1-node-cluster-deprecated`
- Body: `"export_target": "pt_10001"`, `"total_records": 42`
- Body includes `PSYCHIATRY` and `ONCOLOGY` restricted clinical notes with raw text

**Secure outcome:**
- `403 Forbidden` from either the Apigee PEP (if WAF rules were extended to `/api/v1/*`) or from within the Node.js handler (if the patient ID check were implemented)

**Step 3 — Contrast with secure modern FHIR endpoint**
```
GET https://api.caresphere.health/fhir/v4/DocumentReference?patient=pt_10001
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwdF84ODE5MiIsInNjb3BlcyI6WyJwYXRpZW50L09ic2VydmF0aW9uLnJlYWQiXX0...
```
**Secure outcome (per Section 7.1):** `403 Forbidden` — Apigee intercepts this, detects subject `pt_88192` requesting patient `pt_10001`, and rejects before reaching any backend service.

### Finding 3 — Verify unrestricted ePHI in response

In the response body from Step 2:
1. Check whether any returned notes have `"is_restricted": true` — the field is present in the SQL schema (Section 5.2) but ignored by the query.
2. Check whether `"department": "PSYCHIATRY"` records are included — the modern FHIR gateway strips these; the v1 endpoint does not.
3. Flag `content.size: 5120480` (~5.1 MB) as anomalous for a mobile health app performing a routine data request.

---

## Remediation

**Finding 1 (Shadow API):**
1. Complete Epic HLTH-404: physically decommission the legacy Node.js cluster. Coordinate the two remaining hospital integrations to migrate to the FHIR v4 endpoint.
2. If decommission is blocked, extend Apigee WAF rules to cover `/api/v1/*` with the same SMART on FHIR policy enforcement as `/fhir/v4/*`.
3. Implement network segmentation so the legacy cluster is not reachable from the public-facing load balancer.

**Finding 2 (Patient ID BOLA):**
1. Add the patient identity check explicitly documented in the code comments: `if (requestedPatientId !== req.user.patient_id) return res.status(403).json({error: "Access denied"})`.
2. Verify the JWT scope matches the data type being requested (e.g., `patient/DocumentReference.read` required for clinical notes, not `patient/Observation.read`).

**Finding 3 (Unfiltered ePHI):**
1. Add `AND department NOT IN ('PSYCHIATRY') AND is_restricted = FALSE` to the legacy SQL query as an immediate mitigation (matches the Java translator behaviour documented in Section 5.1).
2. The definitive fix is Finding 1: decommission the unfiltered legacy endpoint entirely.
