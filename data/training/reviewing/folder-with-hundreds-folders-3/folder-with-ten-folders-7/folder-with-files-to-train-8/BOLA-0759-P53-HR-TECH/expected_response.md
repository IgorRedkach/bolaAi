# Expected Response

## System
- Domain: HR Tech / Talent Acquisition
- System: JobCore Candidate Portal
- Example ID: BOLA-0759

## Priority Findings

### Finding 1: SSRF via user-controlled URLs (Pattern 5.3)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.3 (SSRF via user-controlled URLs).
An authenticated user from `ORG-7986` can access or modify objects owned by `ORG-21E3`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-7986`
- Response body `tenantId`: `ORG-21E3` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.jobcore-candida.example.com/api/v1/resources/RES-1759" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7986>"
```
Expected: Returns own record with `tenantId: "ORG-7986"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.jobcore-candida.example.com/api/v1/resources/RES-2759" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7986>"
```
**Vulnerable:** Returns `tenantId: "ORG-21E3"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.3
No specific variant documented for Pattern 5.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
