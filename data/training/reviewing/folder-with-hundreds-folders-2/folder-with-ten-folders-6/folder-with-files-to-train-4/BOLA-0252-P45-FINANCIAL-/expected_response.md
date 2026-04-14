# Expected Response

## System
- Domain: Financial Services / Retail Banking
- System: NexaBank Open Finance API
- Example ID: BOLA-0252

## Priority Findings

### Finding 1: Firmware update without signature validation (Pattern 4.5)
**Severity:** Critical
**Category:** Integrity

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 4.5 (Firmware update without signature validation).
An authenticated user from `ORG-33B4` can access or modify objects owned by `ORG-0D6A`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-33B4`
- Response body `tenantId`: `ORG-0D6A` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/resources/RES-1252" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-33B4>"
```
Expected: Returns own record with `tenantId: "ORG-33B4"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/resources/RES-2252" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-33B4>"
```
**Vulnerable:** Returns `tenantId: "ORG-0D6A"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 4.5
No specific variant documented for Pattern 4.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
