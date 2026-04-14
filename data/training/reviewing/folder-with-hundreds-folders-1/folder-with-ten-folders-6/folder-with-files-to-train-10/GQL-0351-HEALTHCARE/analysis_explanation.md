# Analysis Explanation
**Example:** GQL-0351-HEALTHCARE — PatientCore EHR API
**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)

---

## Why This Is a Vulnerability

Pattern 10.2 (Single-User — Parameter escalation) captures session scope extension: the attacker uses their own valid session and escalates the scope of what their session can affect by changing the target ID. In this case, the escalation involves both PHI disclosure and persistence poisoning — the `updatePatient` mutation modifies a cross-tenant patient record's `status` and `ownerId` while also returning the victim's PHI in the response. The attacker does not need a different account; they extend what their own `tenant-1edb` session can reach to include `tenant-85cf` patient `P-2351`.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0351.

- **System Name:** PatientCore EHR API (§1.0)
- **Domain:** Healthcare / EHR Platform
- **Host:** `api.patientcore-ehr-api.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-1edb` (§6.0 HAR `x-tenant-id`)
- **Victim tenant:** `tenant-85cf` (§6.0 HAR; §6.0 response `tenantId`)
- **Victim patient ID:** `P-2351` (§6.0 HAR mutation `id`)
- **Mutation input:** `{status: "approved", ownerId: "attacker-1edb85cf"}` (§6.0 HAR)
- **Sensitive data exposed in response:** `sensitiveField: "CONFIDENTIAL-1edb85cf"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-1edb85cf` (§6.0 response)
- **Vulnerable resolver:** `updatePatient` (§6.0 HAR)
- **Root cause:** `updatePatient` mutation resolver does not cross-check `tenantId` against JWT before applying mutation (§4.0 RISK-GQL-351, §5.0)
- **Redis cache key gap:** Cache keyed by `patientId` only (§2.0)

**Context.txt inconsistency documented:** HAR operation is `updatePatient`; response JSON key is `getPatient`. Inconsistency recorded — HAR operation is authoritative.

## Domain Risk

EHR / Electronic Health Record platforms contain Protected Health Information (PHI) under HIPAA. Cross-tenant access to patient records is a HIPAA breach with mandatory disclosure requirements (up to $1.9M/year per category of violation). Additionally, modifying a patient's `status` to `approved` in a healthcare context could have clinical implications — falsely approving treatment plans, discharge statuses, or insurance pre-authorizations. The `ownerId` reassignment could permanently alter care team attribution.

## What the Model Should Learn

- Pattern 10.2 in healthcare EHR is especially severe because it combines PHI disclosure with persistence poisoning — both HIPAA violations.
- `updatePatient` carrying `ownerId` in the client input is a critical design flaw: ownership of a patient record must be immutable or controlled only by authorized system processes.
- GraphQL mutations that modify and return data (standard in GraphQL) amplify the risk: a single mutation call achieves both read and write unauthorized access.
- Redis cache keyed only by `patientId` allows cross-tenant cache poisoning of PHI — a HIPAA violation independent of the resolver-level flaw.
