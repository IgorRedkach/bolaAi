# Expected Response

## System
- Domain: Real Estate / PropTech
- System: EstateFlow Property API
- Example ID: BOLA-0517

## Priority Findings

### Finding 1: IoT/SCADA node and device ID manipulation (Pattern 1.13)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.13 (IoT/SCADA node and device ID manipulation).
An authenticated user from `ORG-AE78` can access or modify objects owned by `ORG-F830`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-AE78`
- Response body `tenantId`: `ORG-F830` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.estateflow-prop.example.com/api/v1/resources/RES-1517" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AE78>"
```
Expected: Returns own record with `tenantId: "ORG-AE78"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.estateflow-prop.example.com/api/v1/resources/RES-2517" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AE78>"
```
**Vulnerable:** Returns `tenantId: "ORG-F830"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.13
No specific variant documented for Pattern 1.13 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
