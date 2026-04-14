# Expected Response

## System
- Domain: Fintech / Payments Gateway
- System: PayBridge Transaction API
- Example ID: BOLA-6119

## Priority Findings

### Finding 1: State corruption in critical transactions (Pattern 8.5)
**Severity:** Critical
**Category:** Exceptional

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 8.5 (State corruption in critical transactions).
An authenticated user from `ORG-A5BC` can access or modify objects owned by `ORG-9E02`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-A5BC`
- Response body `tenantId`: `ORG-9E02` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/resources/RES-7119" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A5BC>"
```
Expected: Returns own record with `tenantId: "ORG-A5BC"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.paybridge-trans.example.com/api/v1/resources/RES-8119" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-A5BC>"
```
**Vulnerable:** Returns `tenantId: "ORG-9E02"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 8.5
No specific variant documented for Pattern 8.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
