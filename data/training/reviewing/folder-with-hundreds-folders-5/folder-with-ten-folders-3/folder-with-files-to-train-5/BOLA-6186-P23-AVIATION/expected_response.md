# Expected Response

## System
- Domain: Aviation / Flight Ops
- System: AeroOps Flight Management
- Example ID: BOLA-6186

## Priority Findings

### Finding 1: State/session permeability (Pattern 2.3)
**Severity:** Critical
**Category:** BAC

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 2.3 (State/session permeability).
An authenticated user from `ORG-805E` can access or modify objects owned by `ORG-867D`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-805E`
- Response body `tenantId`: `ORG-867D` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.aeroops-flight-.example.com/api/v1/resources/RES-7186" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-805E>"
```
Expected: Returns own record with `tenantId: "ORG-805E"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.aeroops-flight-.example.com/api/v1/resources/RES-8186" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-805E>"
```
**Vulnerable:** Returns `tenantId: "ORG-867D"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 2.3
No specific variant documented for Pattern 2.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
