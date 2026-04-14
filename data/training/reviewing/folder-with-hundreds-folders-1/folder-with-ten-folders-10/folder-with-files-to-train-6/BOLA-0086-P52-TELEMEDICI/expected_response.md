# Expected Response

## System
- Domain: Telemedicine / Remote Care
- System: TeleCare Consultation API
- Example ID: BOLA-0086

## Priority Findings

### Finding 1: Resolver/graph traversal injection (Pattern 5.2)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.2 (Resolver/graph traversal injection).
An authenticated user from `ORG-43EC` can access or modify objects owned by `ORG-D1FE`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-43EC`
- Response body `tenantId`: `ORG-D1FE` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.telecare-consul.example.com/api/v1/resources/RES-1086" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-43EC>"
```
Expected: Returns own record with `tenantId: "ORG-43EC"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.telecare-consul.example.com/api/v1/resources/RES-2086" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-43EC>"
```
**Vulnerable:** Returns `tenantId: "ORG-D1FE"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.2
No specific variant documented for Pattern 5.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
