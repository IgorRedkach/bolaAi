## Findings

1. **BOLA on `GET /api/v2/workspaces/{workspace_id}/state` — missing workspace membership check**: the `WorkspaceService` handler uses `req.params.workspace_id` directly to construct the S3 key (`${targetWorkspace}/terraform.tfstate`) without querying the `workspace_members` PostgreSQL table to verify that the requesting user (`dev_77`) is a member of the target workspace. The code comment explicitly flags the missing check: "The code FAILS to query the PostgreSQL `workspace_members` table." Any authenticated user can substitute any known `workspace_id` in the URL to retrieve that workspace's Terraform state file via the backend's privileged IAM role.

2. **Production database master credentials exposed in Terraform state file**: developer `dev_77` (assigned to `workspace_frontend_dev`) requested `workspace_core_db_prod/terraform.tfstate`. The response contained the `aws_db_instance` resource for `core_transaction_db` including: `address: "core-db-prod-v2.cluster-c9xyz.us-east-1.rds.amazonaws.com"`, `username: "sysadmin_master"`, `password: "SuperSecretProdPassword9921!!"`. These are the plaintext master credentials for the production RDS database.

## Evidence

- **HAR GET request** (`startedDateTime: 2026-04-08T19:16:48.112Z`, elapsed 305 ms): `GET https://api.infrabuild.internal/api/v2/workspaces/workspace_core_db_prod/state`; JWT encodes `sub: dev_77`, `role: frontend_developer`; no request body.
- **Workspace mismatch**: section 3.2 states `dev_77` is assigned to `workspace_frontend_dev` and "strictly prohibited from viewing or triggering deployments for `workspace_core_db_prod`". The `workspace_members` table enforces this via `PRIMARY KEY (workspace_id, user_id)` — but the handler never queries it.
- **HAR response**: HTTP 200 OK, `x-s3-proxy-latency: 290ms`; body contains `"password": "SuperSecretProdPassword9921!!"`, `"username": "sysadmin_master"`, `"address": "core-db-prod-v2.cluster-c9xyz.us-east-1.rds.amazonaws.com"` — full production RDS master credentials directly returned.
- **Flawed handler** (section 6.1): `const params = { Bucket: 'infrabuild-tf-state-prod', Key: \`${targetWorkspace}/terraform.tfstate\` }` followed by `s3.getObject(params).promise()` — uses the backend's IAM role to fetch any state file identified by the user-controlled path parameter. No membership lookup precedes the S3 call.
- **Security note** (section 7.0): the tfstate file includes `publicly_accessible: false` and VPC security group `sg-08a192b3c4d5e` — an attacker with the credentials and VPN access can reach the database directly.

## Reproduction

Step 1 — confirm access to own workspace (baseline):

```bash
curl -i -X GET "https://api.infrabuild.internal/api/v2/workspaces/workspace_frontend_dev/state" \
  -H "Authorization: Bearer <JWT_dev_77_frontend_developer>" \
  -H "Accept: application/json"
```

Expected: HTTP 200 with `workspace_frontend_dev` state file (authorized).

Step 2 — substitute the production workspace ID:

```bash
curl -i -X GET "https://api.infrabuild.internal/api/v2/workspaces/workspace_core_db_prod/state" \
  -H "Authorization: Bearer <JWT_dev_77_frontend_developer>" \
  -H "Accept: application/json"
```

Expected secure outcome: HTTP 403 — `dev_77` is not a member of `workspace_core_db_prod` per `workspace_members` table.  
Observed vulnerable outcome: HTTP 200 with full `terraform.tfstate` for `workspace_core_db_prod` including `"username": "sysadmin_master"`, `"password": "SuperSecretProdPassword9921!!"`, and RDS endpoint `core-db-prod-v2.cluster-c9xyz.us-east-1.rds.amazonaws.com`.

## Remediation

- **Add workspace membership check before S3 fetch**: in the handler, execute `SELECT COUNT(*) FROM workspace_members WHERE user_id = $1 AND workspace_id = $2` before constructing the S3 params. If the count is 0, return HTTP 403 immediately. Never reach the S3 call for unauthorized workspaces.
- **Rotate the exposed credentials immediately**: `SuperSecretProdPassword9921!!` for `sysadmin_master` on `core-db-prod-v2.cluster-c9xyz.us-east-1.rds.amazonaws.com` must be rotated. Audit AWS CloudTrail and VPN access logs for `dev_77` to determine if the credentials were used.
- **Use S3 bucket IAM policies scoped to workspace**: create separate S3 prefixes with IAM resource-based policies that only allow the backend service to access `workspace_frontend_dev/*` for frontend team roles. Do not allow the backend IAM role to fetch any workspace prefix without a corresponding authorization check.
- **Encrypt sensitive fields in tfstate**: configure Terraform backend encryption (`encrypt = true`) and consider using `sensitive = true` output variables to prevent plaintext credential storage in S3 state files.
