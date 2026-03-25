# Internal API — Clinical Trials Data Hub (v2)

Authenticated researchers and site coordinators use JWT. The API does **not** document per-trial or per-site object-level checks.

## REST

- `GET /api/v2/trials/{trialId}` — Returns trial metadata (phase, sponsor, enrollment cap). **Requires Bearer token.** No statement that the caller must be assigned to this trial.
- `GET /api/v2/participants/{participantId}` — Full participant row (PII). **Requires valid token.** Doc does not say the participant must belong to a trial the caller is authorized for.
- `POST /api/v2/exports/batch` — Body: `{ "trialIds": ["..."] }`. Returns ZIP of case report forms for listed trials. **Admin or coordinator role.** No filter by site or trial membership in the spec.
- `GET /api/v2/sites/{siteId}/randomization-log` — Audit log of randomization events for a site. Token required; **no** documented check that the user’s organization owns `siteId`.

## GraphQL (same backend)

- Query `participant(id: ID!) { id trialId medicalHistory redactedNotes }` — Resolver returns nested `investigatorComments` for that participant. **No** documented field-level auth or trial scoping.

## Deprecated (mentioned for migration only)

- `GET /api/v1/legacy/trial-files/{fileId}` — Old file pointer; some clients still call it. Same auth as v2; **ownership of fileId** not described.
