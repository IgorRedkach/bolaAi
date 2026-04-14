# Expected Response

## System
- Domain: Industrial IoT / Manufacturing
- System: ManuControl Robotics Fleet
- Example ID: BOLA-5206

## Priority Findings

### Finding 1: Persistence poisoning via lifecycle actions (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.2 (Persistence poisoning via lifecycle actions).
An authenticated user from `ORG-B411` can access or modify objects owned by `ORG-F437`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-B411`
- Response body `tenantId`: `ORG-F437` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-6206" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B411>"
```
Expected: Returns own record with `tenantId: "ORG-B411"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.manucontrol-rob.example.com/api/v1/resources/RES-7206" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B411>"
```
**Vulnerable:** Returns `tenantId: "ORG-F437"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.2
No specific variant documented for Pattern 4.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
