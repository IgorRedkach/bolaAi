## System

- System: WageFlow Payroll API v2.4.0
- Domain: HR / PAYROLL PROCESSING
- Example ID: BOLA-0096
- Risk ID: RISK-73-096

## Findings

### 1. Pattern 7.3 — Insufficient Logging of Critical Actions: Cross-Tenant DELETE on `/api/v3/items/:id` (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-19DD`. Request: `DELETE /api/v3/items/ITE-2096`. Response: HTTP 200 OK with `"tenantId": "ORG-9225"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-9225"`.

**Pattern 7.3 (Insufficient Logging of Critical Actions)**: DELETE is a critical destructive action that must generate a mandatory audit log entry — especially in payroll systems subject to SOX, labor regulations, and GLBA. The handler executes a cross-tenant DELETE (destroying `ORG-9225`'s payroll item) and returns 200 OK, but generates no audit log entry for the deletion. Compliance audits will not detect the destroyed payroll records. Forensic reconstruction after a breach is impossible.

Section 4.0 confirms: handler lacks tenant/owner filter. Section 3.0: "Application code does NOT use tenant_id in authorization checks." Critical payroll operations — salary modifications, payroll deletions, benefit changes — are not logged with actor identity, tenant context, or authorization decision.

**HR / Payroll impact**: items represent payroll records, salary configurations, or benefit data. A cross-tenant DELETE destroys another employer's payroll records. A cross-tenant PATCH manipulates employee salary data. Both create payroll fraud and compliance violations (SOX) with no audit trail — the attack is permanently undetectable.

### 2. Cross-Tenant Read and PATCH (Pattern 7.3 Extension)

Section 4.0: "GET/PATCH/DELETE `/api/v3/items/:id`" — all verbs share the same unenforced handler. Cross-tenant GET exposes payroll records (salary, PII). Cross-tenant PATCH tampers with payroll data. Neither generates a log entry for the critical access or modification.

## Evidence

- **HAR**: `DELETE /api/v3/items/ITE-2096` with `ORG-19DD` JWT → HTTP 200 → `tenantId: ORG-9225` with `sensitiveData`.
- **Section 4.0 (RISK-73-096)**: Pattern 7.3 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.wageflow-payrol.example.com/api/v3/items/ITE-1096" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-19DD>" \
  -H "X-Tenant-ID: ORG-19DD"
```

Expected: `tenantId: "ORG-19DD"` — own payroll record.

**Step 2 — Cross-tenant payroll record DELETE with no audit log (primary HAR attack):**

```bash
curl -s -X DELETE "https://api.wageflow-payrol.example.com/api/v3/items/ITE-2096" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-19DD>" \
  -H "X-Tenant-ID: ORG-19DD"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-9225"` — payroll record destroyed, no audit log entry generated.

**Step 3 — Cross-tenant payroll PATCH with no critical-action log (Pattern 7.3):**

```bash
curl -s -X PATCH "https://api.wageflow-payrol.example.com/api/v3/items/ITE-2096" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-19DD>" \
  -H "X-Tenant-ID: ORG-19DD" \
  -H "Content-Type: application/json" \
  -d '{"sensitive_data": "salary_tampered", "status": "inactive"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — competitor's payroll record tampered, SOX-required audit log entry missing.

**Step 4 — Cross-tenant payroll read:**

```bash
curl -s "https://api.wageflow-payrol.example.com/api/v3/items/ITE-2096" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-19DD>" \
  -H "X-Tenant-ID: ORG-19DD"
```

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-73-096, unblock DB migration #DB-196).
- **Implement mandatory critical-action logging**: every DELETE, PATCH, and bulk operation must generate an audit log entry with `sub`, `tenant_id`, `item_id`, HTTP method, timestamp, and authorization decision.
- **SOX compliance**: payroll modifications and deletions must be immutably audited with actor attribution.
- **Regression test**: Tenant A token deletes Tenant B `item_id` — assert HTTP 403/404 and no audit suppression.
