# Expected Response

## System
- Domain: Defense Industrial Base
- System: Aegis Vault Secure Repository
- Example ID: BOLA-6355

## Priority Findings

### Finding 1: GraphQL: single endpoint vulnerabilities (Pattern 9.1)
**Severity:** Critical
**Category:** Platform

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 9.1 (GraphQL: single endpoint vulnerabilities).
An authenticated user from `ORG-0BDF` can access or modify objects owned by `ORG-5A85`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-0BDF`
- Response body `tenantId`: `ORG-5A85` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.aegis-vault-sec.example.com/api/v1/resources/RES-7355" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-0BDF>"
```
Expected: Returns own record with `tenantId: "ORG-0BDF"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.aegis-vault-sec.example.com/api/v1/resources/RES-8355" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-0BDF>"
```
**Vulnerable:** Returns `tenantId: "ORG-5A85"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 9.1
No specific variant documented for Pattern 9.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
