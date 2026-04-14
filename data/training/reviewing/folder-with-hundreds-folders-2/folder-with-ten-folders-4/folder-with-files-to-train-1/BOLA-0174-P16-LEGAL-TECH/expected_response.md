# Expected Response

## System
- Domain: Legal Tech / Document Management
- System: LexVault eDiscovery API
- Example ID: BOLA-0174

## Priority Findings

### Finding 1: Write operations without ownership check (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.6 (Write operations without ownership check).
An authenticated user from `ORG-AB9F` can access or modify objects owned by `ORG-5BF1`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-AB9F`
- Response body `tenantId`: `ORG-5BF1` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.lexvault-edisco.example.com/api/v1/resources/RES-1174" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AB9F>"
```
Expected: Returns own record with `tenantId: "ORG-AB9F"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.lexvault-edisco.example.com/api/v1/resources/RES-2174" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AB9F>"
```
**Vulnerable:** Returns `tenantId: "ORG-5BF1"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.6
```bash
# Write-level BOLA
curl -s -X DELETE "/api/v1/resources/RES-2174" -H "Authorization: Bearer <TOKEN_TENANT_ORG-AB9F>"
# Vulnerable: 200 OK / record deleted across tenant boundary
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
