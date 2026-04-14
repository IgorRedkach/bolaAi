# Expected Response

## System
- Domain: HR Tech / Talent Acquisition
- System: JobCore Candidate Portal
- Example ID: BOLA-5808

## Priority Findings

### Finding 1: IoT/SCADA node and device ID manipulation (Pattern 1.13)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.13 (IoT/SCADA node and device ID manipulation).
An authenticated user from `ORG-D6ED` can access or modify objects owned by `ORG-F574`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D6ED`
- Response body `tenantId`: `ORG-F574` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.jobcore-candida.example.com/api/v1/resources/RES-6808" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D6ED>"
```
Expected: Returns own record with `tenantId: "ORG-D6ED"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.jobcore-candida.example.com/api/v1/resources/RES-7808" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D6ED>"
```
**Vulnerable:** Returns `tenantId: "ORG-F574"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.13
No specific variant documented for Pattern 1.13 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
