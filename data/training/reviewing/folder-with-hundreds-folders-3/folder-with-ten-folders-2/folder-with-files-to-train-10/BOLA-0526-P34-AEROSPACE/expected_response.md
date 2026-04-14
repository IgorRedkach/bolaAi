# Expected Response

## System
- Domain: Aerospace / MRO
- System: WingTech Maintenance Portal
- Example ID: BOLA-0526

## Priority Findings

### Finding 1: Implicit trust in callbacks (Pattern 3.4)
**Severity:** Critical
**Category:** Insecure Design

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 3.4 (Implicit trust in callbacks).
An authenticated user from `ORG-62D7` can access or modify objects owned by `ORG-1BB5`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-62D7`
- Response body `tenantId`: `ORG-1BB5` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/resources/RES-1526" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-62D7>"
```
Expected: Returns own record with `tenantId: "ORG-62D7"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.wingtech-mainte.example.com/api/v1/resources/RES-2526" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-62D7>"
```
**Vulnerable:** Returns `tenantId: "ORG-1BB5"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 3.4
No specific variant documented for Pattern 3.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
