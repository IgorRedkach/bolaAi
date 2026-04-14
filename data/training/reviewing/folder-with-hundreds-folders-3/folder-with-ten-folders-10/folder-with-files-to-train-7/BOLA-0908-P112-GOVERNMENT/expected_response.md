# Expected Response

## System
- Domain: Government / Public Safety
- System: FirstResponse CAD Integration
- Example ID: BOLA-0908

## Priority Findings

### Finding 1: Mass assignment via object fields (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.12 (Mass assignment via object fields).
An authenticated user from `ORG-B6F0` can access or modify objects owned by `ORG-83B9`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-B6F0`
- Response body `tenantId`: `ORG-83B9` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.firstresponse-c.example.com/api/v1/resources/RES-1908" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B6F0>"
```
Expected: Returns own record with `tenantId: "ORG-B6F0"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.firstresponse-c.example.com/api/v1/resources/RES-2908" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B6F0>"
```
**Vulnerable:** Returns `tenantId: "ORG-83B9"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.12
```bash
# Mass assignment
curl -s -X PATCH "/api/v1/resources/RES-2908" -H "Authorization: Bearer <TOKEN_TENANT_ORG-B6F0>" -d '{"ownerId":"attacker","tenantId":"ORG-B6F0"}'
# Vulnerable: ownership transferred
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
