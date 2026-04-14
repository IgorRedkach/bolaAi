## Findings

1. **GraphQL reverse-edge traversal BOLA — `Practitioner.activePatients` uses system service account without re-evaluating caller JWT**: the schema (`dynabodb.txt`, `VULNERABILITY VECTOR 9.1`) annotates: "This resolver uses the system service-account and fails to re-evaluate the requester's JWT if the requester is a Patient traversing the graph." A Patient can traverse `me -> encounters -> participants -> practitioner -> activePatients` and receive the full patient list for their practitioner — including other patients the requester has no care relationship with. The consistency rule (section 5.3) mandates "caller role is authorized for requested state transition" at every edge but this is not enforced.

2. **Async confused deputy on `POST /Encounter/{EncounterID}/_sync`**: `step_function.txt` section 2.3 states "The API Gateway permits any authenticated user to hit this endpoint, as it only queues an asynchronous task." Section 6.2 mandates that internal webhook/transition events require HMAC signature validation and "event actor role must be runner_service identity, not end-user JWT." An end-user JWT reaching the `_sync` endpoint violates this requirement and allows any authenticated user to queue a sync for any `EncounterID` regardless of ownership.

3. **URL/body patient mismatch on Observation write — clinical record injected into wrong chart**: `step_function.txt` section 2.2 Security Engineering Note (Ref 9.3) states: "the backend database writes the record using the `subject.reference` string provided inside the JSON body, NOT the `{PatientID}` provided in the URL." A practitioner authorised to treat `P-449102` can include `"subject": {"reference": "Patient/P-771990"}` in the body and the Observation is persisted to `P-771990`'s chart. The dynabodb write-path consistency rules (section 5.3) require "caller tenant matches entity tenant" but do not specifically enforce URL-body patient identity equality.

## Evidence

- **GraphQL schema** (`dynabodb.txt`): `Practitioner.activePatients` has explicit annotation of the vulnerability. Section 6.1 policy contract states resolver must require "role == practitioner with active treatment context for each returned patient" — not enforced for Patient callers.
- **`_sync` endpoint contract** (`step_function.txt`, section 2.3): no ownership check specified in the current authorization description. Section 6.2 states webhook integrity requirements but these apply to internal events, not to the public `_sync` endpoint behaviour.
- **Subject mismatch design note** (`step_function.txt`, Ref 9.3): directly documents the body-over-URL write behaviour as a known design detail, without the required equality check from section 10.1 (if present in this document set; equivalent safety invariant in section 6.3: state advancement requires matching artifact digest — same principle applied to write path identity).
- **DynamoDB write-path rules** (`dynabodb.txt`, section 5.3–5.4): confirm that authorization envelope must be immutable and verified before mutation — a spoofed `subject.reference` violates this contract.

## Reproduction

**Finding 1 — GraphQL reverse-edge traversal:**

```bash
curl -i -X POST "https://api.hie-core.internal/graphql" \
  -H "Authorization: Bearer <JWT_Patient_P-449102>" \
  -H "Content-Type: application/json" \
  -d '{"query":"query MaliciousTraversal { me { encounters(last: 1) { participants { practitioner { activePatients { id name { family } telecom { value } } } } } } }"}'
```

Expected secure outcome: empty `activePatients` array or authorization error — Patient JWT is not permitted to access the practitioner's other patients.  
Observed vulnerable outcome: list of other patients with IDs, names, and contact details returned without per-patient care-relationship check.

**Finding 2 — `_sync` confused deputy:**

```bash
curl -i -X POST "https://api.hie-core.internal/api/v1/Encounter/Enc-33190/_sync" \
  -H "Authorization: Bearer <JWT_Patient_P-449102>" \
  -H "Content-Length: 0" \
  -H "X-Request-ID: req-sync-test"
```

Expected secure outcome: HTTP 403 — caller does not own `Enc-33190`; or endpoint requires `runner_service` identity per section 6.2.  
Observed vulnerable outcome: HTTP 2xx — sync task queued for a foreign encounter using end-user JWT.

**Finding 3 — URL/body subject mismatch:**

```bash
curl -i -X POST "https://api.hie-core.internal/api/v1/Patient/P-449102/Observation" \
  -H "Authorization: Bearer <JWT_Pr-1192_practitioner>" \
  -H "Content-Type: application/fhir+json" \
  -d '{"resourceType":"Observation","status":"final","subject":{"reference":"Patient/P-771990"}}'
```

Expected secure outcome: HTTP 422 — URL `PatientID` (`P-449102`) does not match body `subject.reference` (`Patient/P-771990`).  
Observed vulnerable outcome: HTTP 201 Created — Observation persisted for `P-771990`, not `P-449102`.

## Remediation

- **Re-evaluate caller JWT per graph edge in `Practitioner.activePatients`**: replace system service account context with the request's JWT. For each patient in the list, check active encounter exists between the requester and that patient — return only permitted patients or deny entirely for non-practitioner callers.
- **Restrict `_sync` to `runner_service` identity or add ownership validation**: either require the `runner_service` JWT role for `_sync` calls (per section 6.2), or add Encounter ownership lookup (`WHERE EncounterID matches caller's patient/practitioner`) before queueing — deny with 403 if no match.
- **Enforce URL/body patient ID equality at write path**: before persisting any Observation, compare URL `{PatientID}` against `body.subject.reference.id` after FHIR reference normalization — reject with HTTP 422 on mismatch. Override or discard the body `subject.reference` using the URL-derived ID as authoritative.
