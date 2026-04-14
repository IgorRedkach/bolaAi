# Expected Response

## System
- Domain: Agriculture / Precision Farming
- System: HarvestIQ IoT Platform
- Example ID: BOLA-5971

## Priority Findings

### Finding 1: Anti-forensic capabilities (Pattern 7.2)
**Severity:** Critical
**Category:** Logging Failures

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 7.2 (Anti-forensic capabilities).
An authenticated user from `ORG-FD86` can access or modify objects owned by `ORG-B0EE`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-FD86`
- Response body `tenantId`: `ORG-B0EE` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v1/resources/RES-6971" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-FD86>"
```
Expected: Returns own record with `tenantId: "ORG-FD86"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.harvestiq-iot-p.example.com/api/v1/resources/RES-7971" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-FD86>"
```
**Vulnerable:** Returns `tenantId: "ORG-B0EE"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 7.2
No specific variant documented for Pattern 7.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
