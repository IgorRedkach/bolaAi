## System

- System: JobCore Candidate Portal API v3.3.0
- Domain: HR TECH / RECRUITMENT / APPLICANT TRACKING SYSTEM (ATS)
- Risk ID: RISK-HR-GQL-112

## Findings

### 1. GraphQL Mass Assignment — Candidate Injects `status: OFFER_MADE` to Bypass Recruitment Workflow (Pattern 9.1 + Pattern 1.12)

The Python Django resolver (`candidateResolvers.py`, section 6.1) applies all keys from the client-supplied `input` dictionary to the `Application` model using `setattr()`:

```python
# VULNERABILITY 9.1 & 1.12: Mass Assignment
# The code takes the entire untrusted 'input' dictionary and applies it to the object.
# This allows injection of the 'status' field, which matches a database column name.
for key, value in input.items():
    setattr(app, key, value)  # THE CRITICAL FLAW: Arbitrary key assignment
app.save()
```

The `Application` Django model contains both candidate-writable fields (`candidate_notes`, `resume_link`) and recruiter-controlled state fields (`status`, `hiring_manager_id`) in the same object (section 5.0, RISK-HR-GQL-112). The mutation is intended only for metadata updates (`CandidateUpdateInput` exposes only `candidateNotes`), but the resolver imposes no allowlist — any key that matches a model attribute is written. The candidate injects `status: OFFER_MADE` alongside the benign `candidateNotes` field.

The ownership check (`require_candidate_ownership`) correctly validates that `app_22190` belongs to the calling candidate — but ownership of the object does not authorize writing the `status` field.

**HAR evidence**: POST `https://api.jobcore.com/graphql` with JWT `role: CANDIDATE`, `sub: usr_cand_A`. Mutation input includes `candidateNotes` and injected `status: OFFER_MADE`. Response: HTTP 200 OK. `"status": "OFFER_MADE"` confirmed in response body for application `app_22190` — a previously `REJECTED` application is now in `OFFER_MADE` state.

## Evidence

- **HAR trace**: CANDIDATE JWT → mutation with `status: OFFER_MADE` in input → HTTP 200 OK → `"status": "OFFER_MADE"` returned — recruitment workflow bypassed.
- **Python resolver** (section 6.1): `setattr(app, key, value)` loop with no field allowlist; BOLA check passes (candidate owns the application) but field-level guard is absent.
- **Django model** (section 5.0): `status` with choices including `OFFER_MADE` is on the same model as `candidate_notes` — no `editable=False` or access-layer restriction for CANDIDATE role.
- **Architecture** (section 3.2, RISK-HR-GQL-112): AppSync handles authentication and BOLA; Django resolver relied upon for field-level authorization — but the field-level guard was never implemented.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.jobcore.com
Authorization: Bearer <CANDIDATE_JWT>
Content-Type: application/json

{"query": "mutation ForgeApplicationStatus { updateApplicationMetadata(applicationId: \"app_22190\", input: { candidateNotes: \"Updated resume.\", status: OFFER_MADE }) { applicationId status } }"}
```

`app_22190` must belong to the authenticated candidate (ownership check passes).

Expected secure outcome: GraphQL error — `status` is not a permitted field in `CandidateUpdateInput`; or resolver rejects `status` key for CANDIDATE role.  
Observed vulnerable outcome: HTTP 200 OK, `"status": "OFFER_MADE"` — REJECTED application forged to OFFER_MADE state.

## Remediation

- **Use an explicit field allowlist in the resolver** (RISK-HR-GQL-112): replace the `setattr` loop with explicit assignment: `app.candidate_notes = input.get('candidateNotes')` — never process `status`, `hiring_manager_id`, or any recruiter-only field from CANDIDATE input.
- **Remove `status` from `CandidateUpdateInput` GraphQL type**: the schema type should only declare `candidateNotes` and `resumeLink` — any key not in the schema type definition should be rejected by a strict input validator.
- **Add a role-based field blocklist**: before `app.save()`, check `if 'status' in input and info.context.user.role == 'CANDIDATE': raise PermissionDenied("Status cannot be set by candidates")`.
- **Add `editable=False` for recruiter-only fields in the Django model's form/serializer layer**: this prevents the fields from being modified via any form-based update path, providing a defence-in-depth layer below the resolver.
