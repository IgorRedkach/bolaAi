# Expected Response

## System
- Domain: Fintech / Payments Gateway
- System: PayBridge Transaction API
- Example ID: BOLA-6969

## Priority Findings

### Finding 1: ID swap in own request (Pattern 10.1)
**Severity:** Critical
**Category:** Single-User

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 10.1 (ID swap in own request).
An authenticated user from `ORG-B1F6` can access or modify objects owned by `ORG-A4AC`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-B1F6`
- Response body `tenantId`: `ORG-A4AC` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/resources/RES-7969" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B1F6>"
```
Expected: Returns own record with `tenantId: "ORG-B1F6"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/resources/RES-8969" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-B1F6>"
```
**Vulnerable:** Returns `tenantId: "ORG-A4AC"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 10.1
No specific variant documented for Pattern 10.1 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
