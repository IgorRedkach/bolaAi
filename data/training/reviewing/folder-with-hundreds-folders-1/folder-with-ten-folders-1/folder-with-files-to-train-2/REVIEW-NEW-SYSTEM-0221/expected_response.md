## Findings

1. **Cross-tenant state file access via missing ownership check on `GET /api/v1/projects/{project_id}/state/get-url`**: the `get_state_file_url` controller queries the `iac_projects` table by `project_id` alone (`Project.query.filter_by(project_id=project_id).first()`) without binding the query to the caller's `tenant_id`. The commented-out ownership check (`# if project.tenant_id != user_tenant_id: return 403`) is never executed (RISK-TF-144). An attacker authenticated as `tenant_low_tier` can supply a `project_id` belonging to `tenant_critical_ops` and receive a valid, cryptographically signed S3 pre-signed URL for that tenant's state file.

2. **IaC state file path and content exposure via audit field in response**: the response body includes the field `s3_key_path` constructed as `{project.tenant_id}/{project_id}/prod.tfstate` — exposing both the victim tenant ID and the bucket layout. The pre-signed download URL in `download_url` grants direct S3 access to the `.tfstate` file (valid for 300 seconds per `expires_in_seconds`), which by design stores unencrypted outputs including database passwords, access keys, and network subnet details.

## Evidence

- **HAR GET request** (`startedDateTime: 2026-04-09T18:30:10.010Z`, elapsed 45 ms): `GET https://api.aegis.gov/api/v1/projects/proj_4444X/state/get-url`; JWT encodes `tenant_id: tenant_low_tier`, `clearance: LOW`, `sub: usr_low_8819`; `x-request-id: req-99182-4419a`.
- **HAR response**: HTTP 200 OK, `x-processing-time-ms: 31`; body contains `"s3_key_path": "tenant_critical_ops/proj_4444X/prod.tfstate"` (victim tenant ID in path) and `"download_url": "https://aegis-state-bucket.s3.aws.com/tenant_critical_ops/proj_4444X/prod.tfstate?X-Amz-Algorithm=AWS4-HMAC-SHA256&...&X-Amz-Signature=4a1e5c7d2b9f8a1c5d2e1b9f7a3c8b4d..."` — a valid signed URL valid for 300 seconds.
- **Tenant mismatch**: authenticated `tenant_id` is `tenant_low_tier`; the resolved project record belongs to `tenant_critical_ops` (visible in `s3_key_path`). These are different tenants — the access boundary was crossed.
- **Flawed controller** (section 6.0): `Project.query.filter_by(project_id=project_id).first()` — no `tenant_id` filter. The correct query must be `filter_by(project_id=project_id, tenant_id=user_tenant_id)`.
- **Schema confirms ownership field** (section 5.0): `tenant_id VARCHAR(50) NOT NULL` is annotated as `THE CRITICAL AUTHORIZATION FIELD` in `iac_projects`; the missing WHERE clause binds it.

## Reproduction

Step 1 — confirm the endpoint works for the caller's own project:

```bash
curl -i -X GET "https://api.aegis.gov/api/v1/projects/<OWN_PROJECT_ID>/state/get-url" \
  -H "Authorization: Bearer <JWT_tenant_low_tier>" \
  -H "x-request-id: req-test-001"
```

Expected: HTTP 200, `s3_key_path` contains `tenant_low_tier/...`.

Step 2 — substitute a cross-tenant project ID:

```bash
curl -i -X GET "https://api.aegis.gov/api/v1/projects/proj_4444X/state/get-url" \
  -H "Authorization: Bearer <JWT_tenant_low_tier>" \
  -H "x-request-id: req-99182-4419a"
```

Expected secure outcome: HTTP 403 — `project.tenant_id` (`tenant_critical_ops`) does not match caller's `tenant_id` (`tenant_low_tier`).  
Observed vulnerable outcome: HTTP 200 with `"s3_key_path": "tenant_critical_ops/proj_4444X/prod.tfstate"` and a valid pre-signed S3 download URL expiring in 300 seconds — granting direct access to the victim's Terraform state file containing plaintext secrets.

## Remediation

- **Fix the database query (RISK-TF-144)**: change `Project.query.filter_by(project_id=project_id).first()` to `Project.query.filter_by(project_id=project_id, tenant_id=user_tenant_id).first()` — this single change enforces tenant ownership at the data layer and causes the endpoint to return 404 for cross-tenant project IDs.
- **Remove `s3_key_path` from the response**: the S3 key path exposes the victim's `tenant_id` and bucket layout even before the download URL is used — strip this field from the API response entirely.
- **Enforce clearance level check**: the JWT contains `clearance_level`; the project record has a `clearance_level` column — validate that the caller's clearance is sufficient for the target project before generating the URL.
- **Shorten pre-signed URL lifetime and scope by IP**: reduce the `expires_in_seconds` from 300 to the minimum needed and add an `aws:SourceIp` condition in the pre-sign policy to the caller's source IP, limiting replay window.
