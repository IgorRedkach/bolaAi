# Expected Response

## System
- Domain: Blockchain / DeFi
- System: ChainVault DeFi API
- Example ID: BOLA-6434

## Priority Findings

### Finding 1: SSRF via user-controlled URLs (Pattern 5.3)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.3 (SSRF via user-controlled URLs).
An authenticated user from `ORG-2127` can access or modify objects owned by `ORG-37D9`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-2127`
- Response body `tenantId`: `ORG-37D9` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.chainvault-defi.example.com/api/v1/resources/RES-7434" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2127>"
```
Expected: Returns own record with `tenantId: "ORG-2127"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.chainvault-defi.example.com/api/v1/resources/RES-8434" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-2127>"
```
**Vulnerable:** Returns `tenantId: "ORG-37D9"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.3
No specific variant documented for Pattern 5.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
