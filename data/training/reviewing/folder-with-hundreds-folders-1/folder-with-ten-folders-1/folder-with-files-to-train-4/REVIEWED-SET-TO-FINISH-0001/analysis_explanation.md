## Analysis reasoning

I reviewed the Tri-State HIE-Core v4.2.1 developer guide (`dev_guide.txt`), GraphQL schema (`graphql.txt`), and HAR trace (`har.txt`) as a multi-artifact set.

1. **URL/body subject mismatch — HAR-driven confirmation**: the HAR POST to `/Patient/P-449102/Observation` carries `"subject": {"reference": "Patient/P-999999"}`. The dev_guide (section 2.2, Ref 9.3) explicitly states the backend uses the body's `subject.reference` for persistence, not the URL `{PatientID}`. The OPA encounter check uses the URL patient — `P-449102` has an encounter with `Pr-1192`, so the request is allowed — but the written record is associated with `P-999999`. This is a split-horizon authorization bypass: the check context and the write context use different patient identifiers. The consistency addendum (section 10.1) documents the required fix but confirms it is not yet implemented.

2. **GraphQL reverse-edge traversal — schema annotation as evidence**: the `Practitioner.activePatients` resolver comment in `graphql.txt` is the primary evidence — it directly states the system service account is used and caller JWT context is not re-evaluated. Section 6.1 defines the required policy. The consistency addendum (section 10.3) repeats the rule: "Graph traversal resolvers must re-evaluate authorization at each relationship edge." The HAR note at the end of `har.txt` states "nested graph edge escalation from me->encounters->practitioner->activePatients" is the attack vector.

3. **Confused deputy on `_sync`** — documentation confirms: `dev_guide.txt` section 2.3 states "The API Gateway permits any authenticated user to hit this endpoint." Section 10.2 states ownership validation is required but must be done within 150 ms, and if it cannot, must deny rather than allow optimistically — this is a documented intended behavior that conflicts with the actual gateway rule ("any authenticated user").

4. **Three distinct vulnerability classes**: these are three independent security flaws — (a) URL/body mismatch is a missing input validation / confused deputy in FHIR write path, (b) GraphQL BOLA via reverse-edge is a graph traversal authorization gap, (c) `_sync` is an access-control omission on an async endpoint. Each requires a different fix.

5. **HIPAA/FHIR context**: patient chart integrity and access boundaries are HIPAA-regulated. Writing clinical Observations to the wrong patient chart (`P-999999` instead of `P-449102`) constitutes unauthorized ePHI modification. Exposing other patients' identifiers via the GraphQL traversal constitutes unauthorized ePHI access.
