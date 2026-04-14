# Expected Response

## System
- Domain: Retail / Loyalty Programme
- System: RewardCore Loyalty API
- Example ID: BOLA-6572

## Priority Findings

### Finding 1: Firmware update without signature validation (Pattern 4.5)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.5 (Firmware update without signature validation).
An authenticated user from `ORG-F1C8` can access or modify objects owned by `ORG-5492`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-F1C8`
- Response body `tenantId`: `ORG-5492` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v1/resources/RES-7572" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F1C8>"
```
Expected: Returns own record with `tenantId: "ORG-F1C8"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v1/resources/RES-8572" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-F1C8>"
```
**Vulnerable:** Returns `tenantId: "ORG-5492"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.5
No specific variant documented for Pattern 4.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
