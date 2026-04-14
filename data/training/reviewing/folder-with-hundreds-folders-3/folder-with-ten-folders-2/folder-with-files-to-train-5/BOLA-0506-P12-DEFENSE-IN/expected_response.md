# Expected Response

## System
- Domain: Defense Industrial Base
- System: Aegis Vault Secure Repository
- Example ID: BOLA-0506

## Priority Findings

### Finding 1: Related or linked resources (Pattern 1.2)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.2 (Related or linked resources).
An authenticated user from `ORG-C9B4` can access or modify objects owned by `ORG-14D5`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-C9B4`
- Response body `tenantId`: `ORG-14D5` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.aegis-vault-sec.example.com/api/v1/resources/RES-1506" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-C9B4>"
```
Expected: Returns own record with `tenantId: "ORG-C9B4"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.aegis-vault-sec.example.com/api/v1/resources/RES-2506" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-C9B4>"
```
**Vulnerable:** Returns `tenantId: "ORG-14D5"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.2
No specific variant documented for Pattern 1.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
