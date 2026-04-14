# Expected Response

## System
- Domain: B2B SaaS / CRM
- System: PipelinePro Sales API
- Example ID: BOLA-0984

## Priority Findings

### Finding 1: Industrial protocol injection (Pattern 5.4)
**Severity:** Critical
**Category:** Injection

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 5.4 (Industrial protocol injection).
An authenticated user from `ORG-4F7E` can access or modify objects owned by `ORG-11C4`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-4F7E`
- Response body `tenantId`: `ORG-11C4` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v1/resources/RES-1984" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-4F7E>"
```
Expected: Returns own record with `tenantId: "ORG-4F7E"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.pipelinepro-sal.example.com/api/v1/resources/RES-2984" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-4F7E>"
```
**Vulnerable:** Returns `tenantId: "ORG-11C4"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 5.4
No specific variant documented for Pattern 5.4 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
