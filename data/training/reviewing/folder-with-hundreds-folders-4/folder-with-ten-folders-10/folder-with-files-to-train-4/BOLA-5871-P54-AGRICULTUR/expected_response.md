# Expected Response

## System
- Domain: Agriculture / Precision Farming
- System: HarvestIQ IoT Platform
- Example ID: BOLA-5871

## Priority Findings

### Finding 1: Industrial protocol injection (Pattern 5.4)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.4 (Industrial protocol injection).
An authenticated user from `ORG-5DAD` can access or modify objects owned by `ORG-F1FD`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-5DAD`
- Response body `tenantId`: `ORG-F1FD` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v1/resources/RES-6871" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-5DAD>"
```
Expected: Returns own record with `tenantId: "ORG-5DAD"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v1/resources/RES-7871" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-5DAD>"
```
**Vulnerable:** Returns `tenantId: "ORG-F1FD"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.4
No specific variant documented for Pattern 5.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
