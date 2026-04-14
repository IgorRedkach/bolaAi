# Expected Response

## System
- Domain: Financial Services / Retail Banking
- System: NexaBank Open Finance API
- Example ID: BOLA-0902

## Priority Findings

### Finding 1: Write operations without ownership check (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.6 (Write operations without ownership check).
An authenticated user from `ORG-ECAF` can access or modify objects owned by `ORG-94B9`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-ECAF`
- Response body `tenantId`: `ORG-94B9` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/resources/RES-1902" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-ECAF>"
```
Expected: Returns own record with `tenantId: "ORG-ECAF"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/resources/RES-2902" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-ECAF>"
```
**Vulnerable:** Returns `tenantId: "ORG-94B9"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.6
```bash
# Write-level BOLA
curl -s -X DELETE "/api/v1/resources/RES-2902" -H "Authorization: Bearer <TOKEN_TENANT_ORG-ECAF>"
# Vulnerable: 200 OK / record deleted across tenant boundary
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
