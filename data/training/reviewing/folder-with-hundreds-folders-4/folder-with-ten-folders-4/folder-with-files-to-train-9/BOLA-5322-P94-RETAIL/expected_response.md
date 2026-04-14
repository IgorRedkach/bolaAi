# Expected Response

## System
- Domain: Retail / Loyalty Programme
- System: RewardCore Loyalty API
- Example ID: BOLA-5322

## Priority Findings

### Finding 1: SCADA and ICS (Pattern 9.4)
**Severity:** Critical
**Category:** Platform

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 9.4 (SCADA and ICS).
An authenticated user from `ORG-003C` can access or modify objects owned by `ORG-D9CF`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-003C`
- Response body `tenantId`: `ORG-D9CF` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v1/resources/RES-6322" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-003C>"
```
Expected: Returns own record with `tenantId: "ORG-003C"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.rewardcore-loya.example.com/api/v1/resources/RES-7322" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-003C>"
```
**Vulnerable:** Returns `tenantId: "ORG-D9CF"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 9.4
No specific variant documented for Pattern 9.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
