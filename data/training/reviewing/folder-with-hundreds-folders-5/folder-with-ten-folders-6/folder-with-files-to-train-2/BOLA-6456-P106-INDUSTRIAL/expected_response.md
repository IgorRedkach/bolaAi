# Expected Response

## System
- Domain: Industrial IoT / Manufacturing
- System: ManuControl Robotics Fleet
- Example ID: BOLA-6456

## Priority Findings

### Finding 1: Subscription / webhook hijacking (Pattern 10.6)
**Severity:** Critical
**Category:** Single-User

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 10.6 (Subscription / webhook hijacking).
An authenticated user from `ORG-D6C2` can access or modify objects owned by `ORG-0D0A`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D6C2`
- Response body `tenantId`: `ORG-0D0A` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-7456" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D6C2>"
```
Expected: Returns own record with `tenantId: "ORG-D6C2"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-8456" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D6C2>"
```
**Vulnerable:** Returns `tenantId: "ORG-0D0A"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 10.6
No specific variant documented for Pattern 10.6 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
