## Findings

1. **SSRF via unsanitised `resource_url` parameter at `POST /api/v3/resources/import-metadata` (RISK-IAC-099)**: the Flask `import_resource_metadata` function passes the caller-supplied `resource_url` directly to `requests.get()` without any denylist for internal or S3-internal addresses. An attacker authenticated as tenant `org-low-991A` can set `resource_url` to `https://cloudforge-state.s3.amazonaws.com/tenant-critical-ops/prod-db/prod.tfstate` — an S3 path belonging to a different tenant — and the service fetches it using its own privileged IAM role (the only role with S3 read access per section 2.2).

2. **Sensitive data reflected via verbose error handler**: the `handle_import_error` function reflects up to 1024 bytes of the fetched file content in the HTTP response when JSON parsing fails (`leakage_content = e.doc[:1024]`). The HAR 500 response body includes the first kilobytes of the victim tenant's `.tfstate` file, including the plaintext database password `MySecretDBPassw0rd991X` (marked `"sensitive": true` in the state file) and internal subnet IDs.

## Evidence

- **HAR POST request** (`startedDateTime: 2026-04-09T18:50:05.115Z`, elapsed 345 ms): `POST https://api.cloudforge.io/api/v3/resources/import-metadata`; JWT encodes `tenant_id: org-low-991A`, `role: USER`; body `{"resource_url": "https://cloudforge-state.s3.amazonaws.com/tenant-critical-ops/prod-db/prod.tfstate"}`.
- **Tenant mismatch**: the authenticated caller's `tenant_id` is `org-low-991A`; the S3 path in `resource_url` contains `tenant-critical-ops` — a different tenant's state prefix (section 3.2 key structure: `s3://cloudforge-state/{tenant_id}/{project_name}/prod.tfstate`).
- **HAR response**: HTTP 500, `x-process-time-ms: 290`; body `{"error_code": "IMPORT_PARSING_FAILURE", "detail": "Parsing failed for URL https://cloudforge-state.s3.amazonaws.com/tenant-critical-ops/prod-db/prod.tfstate. Content start: {\"version\": 4, \"terraform_version\": \"1.4.6\", ..., \"database_password\": {\"value\": \"MySecretDBPassw0rd991X\", \"type\": \"string\", \"sensitive\": true}, ..."}` — the victim's plaintext credential is directly embedded in the attacker's error response.
- **Flawed code** (section 6.0): `response = requests.get(resource_url, timeout=5)` — no URL scheme validation, no network denylist, no check that the URL path prefix matches the caller's `tenant_id`.
- **Error handler leakage** (section 6.0, `handle_import_error`): `leakage_content = e.doc[:1024]` followed by inclusion in the JSON response — intended as a debug aid, this becomes the exfiltration channel.

## Reproduction

Step 1 — confirm the endpoint is reachable with tenant `org-low-991A`:

```bash
curl -i -X POST "https://api.cloudforge.io/api/v3/resources/import-metadata" \
  -H "Authorization: Bearer <JWT_org-low-991A>" \
  -H "Content-Type: application/json" \
  -d '{"resource_url": "https://us-east-1.console.aws.amazon.com/ec2/vms/i-12345"}'
```

Expected: HTTP 200 with `"status": "METADATA_SUCCESS"` for a legitimately accessible resource.

Step 2 — redirect the service to fetch a cross-tenant S3 state file:

```bash
curl -i -X POST "https://api.cloudforge.io/api/v3/resources/import-metadata" \
  -H "Authorization: Bearer <JWT_org-low-991A>" \
  -H "Content-Type: application/json" \
  -d '{"resource_url": "https://cloudforge-state.s3.amazonaws.com/tenant-critical-ops/prod-db/prod.tfstate"}'
```

Expected secure outcome: HTTP 403 — `resource_url` host/path does not match caller's tenant scope, or the URL is on the internal-endpoint denylist.  
Observed vulnerable outcome: HTTP 500 `IMPORT_PARSING_FAILURE` with `detail` field containing the beginning of the Terraform state file, including `"database_password": {"value": "MySecretDBPassw0rd991X", "sensitive": true}` belonging to `tenant-critical-ops`.

## Remediation

- **Implement URL denylist and tenant path validation (RISK-IAC-099)**: before calling `requests.get()`, parse the URL and (a) reject any scheme other than `https`, (b) reject hostnames matching RFC1918 ranges, link-local (`169.254.x.x`), loopback, and internal service patterns including `*.s3.amazonaws.com`, (c) if an S3 URL is permitted at all, validate that the path prefix matches the calling tenant's `tenant_id` extracted from the JWT — reject any mismatch with HTTP 403.
- **Remove the `e.doc` reflection from `handle_import_error`**: the verbose content leak is the proximate exfiltration vector; replace with a generic error message (`"Content parsing failed. Contact support."`) that does not include any portion of the fetched content.
- **Enforce least-privilege IAM at the resource layer**: the Resource Import Service should not use the Terraform Executor's IAM role. Create a separate, scoped IAM role for the import service with explicit S3 bucket policy `Deny` for the state bucket (`cloudforge-state`).
- **Add SSRF-specific integration tests**: for every URL-accepting endpoint, test redirection to `169.254.169.254`, `127.0.0.1`, internal hostnames, and cross-tenant S3 paths — all must return 4xx, not 2xx or 5xx with content.
