## Findings

1. **Cache-key authorization mismatch on `GET /api/v2/patients/{patient_id}/clinical-summary`**: the Envoy gateway's cache policy hashes only the HTTP method and URI path (`headers_to_include: []` — the `Authorization` header is explicitly excluded from the cache key). A response cached for one authenticated physician is served to any subsequent requester with the same URI regardless of their identity. This completely bypasses the backend FastAPI "Care Team" authorization check (`SELECT count(*) FROM care_teams WHERE provider_npi = $1 AND patient_id = $2`), because the cache returns data before the request ever reaches the backend.

2. **HIPAA ePHI exposure**: patient `P-7712`'s full clinical summary — including `full_name: "Richard Roe"`, `date_of_birth: "1965-04-12"`, `ssn_last_four: "4491"`, active diagnoses with ICD-10 codes, and clinical encounter notes — was served to a physician (`npi: 998877665`) with no documented care relationship to this patient. The access generated no audit log in the downstream PostgreSQL database (section 6.0: "no auditable log of the unauthorized read is ever generated").

## Evidence

- **HAR entry 1** (authorized cache MISS): `GET https://api.vitastream.health/api/v2/patients/P-7712/clinical-summary` at `2026-04-08T09:15:02.100Z`; JWT encodes `sub: Dr.Smith`, `npi: 112255889`; response HTTP 200, `x-cache: MISS`, `age: 0`, `x-envoy-upstream-service-time: 342` — backend was invoked, care team check passed.

- **HAR entry 2** (unauthorized cache HIT): same URL at `2026-04-08T09:15:47.550Z` (45 seconds later); JWT encodes `sub: Dr.Jones`, `npi: 998877665` (a different physician); response HTTP 200, **`x-cache: HIT`**, **`age: 45`**, **`x-envoy-upstream-service-time: 0`** — backend was never invoked; identical payload served including patient `P-7712`'s full demographics, diagnoses, and encounter notes belonging to Dr. Smith's care domain.

- **Cache key configuration** (section 2.2 Envoy YAML): `headers_to_include: []` with comment "Should include 'Authorization'". The cache key is `SHA256("GET" + "/api/v2/patients/P-7712/clinical-summary")` — identity-agnostic. Any authenticated request to this URI within the 900-second TTL window receives the cached response.

- **Backend authorization is unreachable on cache HIT**: the backend "Care Team" check (section 3.2) is only executed when the gateway routes to `backend_data_lake` — which only happens on a cache MISS. Dr. Jones's request never reached the backend, so the care team check was never evaluated.

- **No audit trail**: section 6.0 explicitly states that cache hits bypass the backend and thus generate no auditable log entry — Dr. Jones's unauthorized access to patient P-7712's ePHI is invisible to the PostgreSQL audit system.

## Reproduction

Step 1 — Dr. Smith (authorized care team member) makes the first request, populating the cache:

```bash
curl -i -X GET "https://api.vitastream.health/api/v2/patients/P-7712/clinical-summary" \
  -H "Authorization: Bearer <JWT_Dr_Smith_npi_112255889>" \
  -H "Accept: application/json"
```

Expected: HTTP 200, `x-cache: MISS`, `x-envoy-upstream-service-time` > 0 (backend invoked).

Step 2 — within 15 minutes, Dr. Jones (no care team relationship) makes the identical request:

```bash
curl -i -X GET "https://api.vitastream.health/api/v2/patients/P-7712/clinical-summary" \
  -H "Authorization: Bearer <JWT_Dr_Jones_npi_998877665>" \
  -H "Accept: application/json"
```

Expected secure outcome: HTTP 403 — `npi: 998877665` has no care team relationship with `P-7712`; or cache returns a 403 because authorization is re-validated.  
Observed vulnerable outcome: HTTP 200, `x-cache: HIT`, `age: 45`, `x-envoy-upstream-service-time: 0` — patient `P-7712`'s full ePHI returned without any authorization check.

## Remediation

- **Include `Authorization` header in the cache key**: in the Envoy cache configuration, change `headers_to_include: []` to `headers_to_include: ["Authorization"]`. This makes the cache key identity-aware, ensuring Dr. Jones's request generates a cache MISS and routes to the backend for authorization.
- **Alternatively, disable caching for ePHI endpoints entirely**: for HIPAA-regulated ePHI responses, the performance benefit of caching does not justify the authorization bypass risk. Remove the cache policy for all paths under `/api/v2/patients/`.
- **Emit a cache-layer audit log on every HIT**: even with corrected cache keys, log all cache hits for patient data endpoints — include the NPI, patient ID, cache key, and timestamp — to maintain HIPAA audit trail continuity regardless of whether the backend was invoked.
- **Add a post-cache authorization validation layer**: implement a lightweight authorization middleware at the gateway level that validates care team membership even for cache hits, before serving the response — this provides defense-in-depth against future cache key misconfigurations.
