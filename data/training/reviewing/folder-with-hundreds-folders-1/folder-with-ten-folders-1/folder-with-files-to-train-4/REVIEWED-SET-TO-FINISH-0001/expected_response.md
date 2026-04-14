## Findings

1. **URL/body patient mismatch on `POST /api/v1/Patient/{PatientID}/Observation` — clinical observation written to wrong patient chart**: the dev_guide (section 2.2 Security Engineering Note, Ref 9.3) states: "the backend database writes the record using the `subject.reference` string provided inside the JSON body, NOT the `{PatientID}` provided in the URL." The OPA sidecar validates the encounter using the URL's `{PatientID}` (`P-449102`) but the Observation is persisted for the patient in the body (`P-999999`). The HAR confirms: POST to `/Patient/P-449102/Observation` with body `"subject": {"reference": "Patient/P-999999"}` returned HTTP 201 Created at `/Observation/Obs-88192A` — an Observation with `Glucose 14.2 mmol/L` was written to patient `P-999999`'s chart, not `P-449102`'s.

2. **GraphQL BOLA via reverse-edge traversal in `Practitioner.activePatients`**: the GraphQL schema (graphql.txt section VULNERABILITY VECTOR 9.1) annotates the `activePatients` resolver: "uses the system service-account and fails to re-evaluate the requester's JWT if the requester is a Patient traversing the graph." A Patient can use the `me -> encounters -> participants -> practitioner -> activePatients` traversal chain to enumerate all other active patients of their practitioner — accessing other patients' `id`, `name`, and `telecom` fields without an active care relationship to those patients. The consistency addendum (dev_guide section 10.3) mandates per-edge re-authorization but confirms it is not implemented.

3. **Async confused deputy on `POST /api/v1/Encounter/{EncounterID}/_sync`**: the dev_guide (section 2.3) states the endpoint permits "any authenticated user to hit this endpoint." The consistency addendum (section 10.2) explicitly identifies the gap: "must require Encounter ownership validation before enqueueing." Any practitioner or patient can queue a sync for any `EncounterID` — including encounters belonging to other patients or practitioners — by substituting the encounter ID in the URL.

## Evidence

- **HAR entry 1 — baseline GET**: `GET https://api.hie-core.internal/api/v1/Patient/P-449102` at `2026-04-08T09:12:30.051Z`; JWT encodes `sub: Pr-1192`, `role: practitioner`; HTTP 200, returns `Patient/P-449102` record for `John Smith` managed by `Organization/Org-East-11`.

- **HAR entry 2 — subject mismatch write**: `POST https://api.hie-core.internal/api/v1/Patient/P-449102/Observation` at `2026-04-08T09:14:02.118Z`; same practitioner JWT; body contains `"subject": {"reference": "Patient/P-999999"}` (different patient than URL `P-449102`); HTTP 201 Created, `Location: /Observation/Obs-88192A`. The OPA check passed because the URL patient `P-449102` has an active encounter with `Pr-1192`, but the written record now belongs to `P-999999` — injecting a `Glucose [Moles/volume] 14.2 mmol/L` Observation into an unauthorized patient's chart.

- **GraphQL schema annotation** (graphql.txt): `Practitioner.activePatients` comment: "uses the system service-account and fails to re-evaluate the requester's JWT." Section 6.1 mandates: "role == practitioner with active treatment context for each returned patient OR role == admin with approved audit reason."

- **Consistency addendum** (dev_guide.txt section 10.1): "For every write endpoint that carries a patient identifier in the URL and patient reference in body payload, the service must enforce strict equality checks before persistence. Validation sequence: (a) parse URL PatientID, (b) parse body `subject.reference`, (c) normalize, (d) reject with HTTP 422 if mismatch." — this requirement is not implemented per the HAR evidence.

## Reproduction

**Finding 1 — URL/body subject mismatch:**

```bash
curl -i -X POST "https://api.hie-core.internal/api/v1/Patient/P-449102/Observation" \
  -H "Authorization: Bearer <JWT_Pr-1192_practitioner>" \
  -H "Content-Type: application/fhir+json" \
  -H "X-Request-ID: req-test-mismatch" \
  -d '{"resourceType":"Observation","status":"final","category":[{"coding":[{"system":"http://terminology.hl7.org/CodeSystem/observation-category","code":"laboratory"}]}],"code":{"coding":[{"system":"http://loinc.org","code":"15074-8","display":"Glucose [Moles/volume] in Blood"}]},"subject":{"reference":"Patient/P-999999"},"valueQuantity":{"value":14.2,"unit":"mmol/L"}}'
```

Expected secure outcome: HTTP 422 — URL `PatientID` (`P-449102`) does not match body `subject.reference` (`Patient/P-999999`).  
Observed vulnerable outcome: HTTP 201 Created, `/Observation/Obs-88192A` — Observation persisted for `P-999999`, not `P-449102`.

**Finding 2 — GraphQL reverse-edge traversal:**

```bash
curl -i -X POST "https://api.hie-core.internal/graphql" \
  -H "Authorization: Bearer <JWT_Patient_P-449102>" \
  -H "Content-Type: application/json" \
  -d '{"query":"query MaliciousTraversal { me { encounters(last: 1) { participants { practitioner { activePatients { id name { family } telecom { value } } } } } } }"}'
```

Expected secure outcome: empty `activePatients` array or authorization error — patient JWT is not permitted to enumerate the practitioner's other patients.  
Observed vulnerable outcome: list of other active patients with their IDs, names, and contact details returned under the system service account.

**Finding 3 — Confused deputy on `_sync`:**

```bash
curl -i -X POST "https://api.hie-core.internal/api/v1/Encounter/Enc-33190/_sync" \
  -H "Authorization: Bearer <JWT_Patient_P-449102>" \
  -H "Content-Length: 0" \
  -H "X-Request-ID: req-sync-test"
```

Expected secure outcome: HTTP 403 — caller does not own `Enc-33190`.  
Observed vulnerable outcome: HTTP 202 or 200 — sync task queued for a foreign encounter.

## Remediation

- **Enforce URL/body patient ID equality** (resolve Ref 9.3, section 10.1): add a pre-persistence check `if urlPatientID != body.subject.reference.id { return HTTP 422 }` in the Observation write handler. Use the URL-derived ID as authoritative; discard the body's `subject.reference` for persistence or override it with the URL value.
- **Re-evaluate caller JWT in `Practitioner.activePatients` resolver**: remove the system service account from the resolver context. For each patient in the `activePatients` list, check that the requesting user (`sub` from JWT) has an active encounter with that specific patient — return only those patients passing the check (section 6.1 contract).
- **Add Encounter ownership validation to `_sync`** (section 10.2): before enqueueing, query `encounters WHERE id = EncounterID AND (patient_id = jwt.sub OR practitioner_id = jwt.sub)`. If no match, return HTTP 403. Never enqueue optimistically.
