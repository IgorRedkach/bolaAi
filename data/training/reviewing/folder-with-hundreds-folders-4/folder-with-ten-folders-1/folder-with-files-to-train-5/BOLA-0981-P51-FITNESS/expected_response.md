# Expected Response

## System
- Domain: Fitness / Wearables
- System: VitalTrack Health API
- Example ID: BOLA-0981

## Priority Findings

### Finding 1: Authorization-bypass injection (Pattern 5.1)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.1 (Authorization-bypass injection).
An authenticated user from `ORG-CA1A` can access or modify objects owned by `ORG-B06A`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-CA1A`
- Response body `tenantId`: `ORG-B06A` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v1/resources/RES-1981" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CA1A>"
```
Expected: Returns own record with `tenantId: "ORG-CA1A"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.vitaltrack-heal.example.com/api/v1/resources/RES-2981" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-CA1A>"
```
**Vulnerable:** Returns `tenantId: "ORG-B06A"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.1
No specific variant documented for Pattern 5.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
