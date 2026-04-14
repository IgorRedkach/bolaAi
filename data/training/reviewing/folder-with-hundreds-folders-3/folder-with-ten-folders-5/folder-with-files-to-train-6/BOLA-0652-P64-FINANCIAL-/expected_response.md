# Expected Response

## System
- Domain: Financial Services / Retail Banking
- System: NexaBank Open Finance API
- Example ID: BOLA-0652

## Priority Findings

### Finding 1: Cloud storage bucket and network exposure (Pattern 6.4)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.4 (Cloud storage bucket and network exposure).
An authenticated user from `ORG-AD8A` can access or modify objects owned by `ORG-C100`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-AD8A`
- Response body `tenantId`: `ORG-C100` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/resources/RES-1652" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AD8A>"
```
Expected: Returns own record with `tenantId: "ORG-AD8A"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.nexabank-open-f.example.com/api/v1/resources/RES-2652" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AD8A>"
```
**Vulnerable:** Returns `tenantId: "ORG-C100"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.4
No specific variant documented for Pattern 6.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
