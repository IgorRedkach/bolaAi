# Expected Response

## System
- Domain: Data Analytics / BI Platform
- System: InsightGraph Analytics API
- Example ID: BOLA-5494

## Priority Findings

### Finding 1: SSRF via user-controlled URLs (Pattern 5.3)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.3 (SSRF via user-controlled URLs).
An authenticated user from `ORG-7DDB` can access or modify objects owned by `ORG-4124`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-7DDB`
- Response body `tenantId`: `ORG-4124` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.insightgraph-an.example.com/api/v1/resources/RES-6494" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7DDB>"
```
Expected: Returns own record with `tenantId: "ORG-7DDB"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.insightgraph-an.example.com/api/v1/resources/RES-7494" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-7DDB>"
```
**Vulnerable:** Returns `tenantId: "ORG-4124"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.3
No specific variant documented for Pattern 5.3 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
