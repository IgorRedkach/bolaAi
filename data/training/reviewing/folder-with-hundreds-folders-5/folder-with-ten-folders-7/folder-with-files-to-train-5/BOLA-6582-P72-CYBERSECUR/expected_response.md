# Expected Response

## System
- Domain: Cybersecurity / SIEM
- System: ThreatLens SOC Platform
- Example ID: BOLA-6582

## Priority Findings

### Finding 1: Anti-forensic capabilities (Pattern 7.2)
**Severity:** Critical
**Category:** Logging Failures

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 7.2 (Anti-forensic capabilities).
An authenticated user from `ORG-AA8A` can access or modify objects owned by `ORG-8D9C`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-AA8A`
- Response body `tenantId`: `ORG-8D9C` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.threatlens-soc-.example.com/api/v1/resources/RES-7582" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AA8A>"
```
Expected: Returns own record with `tenantId: "ORG-AA8A"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.threatlens-soc-.example.com/api/v1/resources/RES-8582" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-AA8A>"
```
**Vulnerable:** Returns `tenantId: "ORG-8D9C"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 7.2
No specific variant documented for Pattern 7.2 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
