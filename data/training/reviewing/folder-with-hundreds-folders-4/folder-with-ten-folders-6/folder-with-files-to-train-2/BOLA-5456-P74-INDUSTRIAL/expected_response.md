# Expected Response

## System
- Domain: Industrial IoT / Manufacturing
- System: ManuControl Robotics Fleet
- Example ID: BOLA-5456

## Priority Findings

### Finding 1: Incomplete log context (Pattern 7.4)
**Severity:** Critical
**Category:** Logging Failures

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 7.4 (Incomplete log context).
An authenticated user from `ORG-79BD` can access or modify objects owned by `ORG-6248`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-79BD`
- Response body `tenantId`: `ORG-6248` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-6456" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-79BD>"
```
Expected: Returns own record with `tenantId: "ORG-79BD"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-7456" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-79BD>"
```
**Vulnerable:** Returns `tenantId: "ORG-6248"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 7.4
No specific variant documented for Pattern 7.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
