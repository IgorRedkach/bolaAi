# Expected Response

## System
- Domain: Telemedicine / Remote Care
- System: TeleCare Consultation API
- Example ID: BOLA-0236

## Priority Findings

### Finding 1: Mass assignment via object fields (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 1.12 (Mass assignment via object fields).
An authenticated user from `ORG-D5DF` can access or modify objects owned by `ORG-AFCB`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D5DF`
- Response body `tenantId`: `ORG-AFCB` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.telecare-consul.example.com/api/v1/resources/RES-1236" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D5DF>"
```
Expected: Returns own record with `tenantId: "ORG-D5DF"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.telecare-consul.example.com/api/v1/resources/RES-2236" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D5DF>"
```
**Vulnerable:** Returns `tenantId: "ORG-AFCB"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 1.12
```bash
# Mass assignment
curl -s -X PATCH "/api/v1/resources/RES-2236" -H "Authorization: Bearer <TOKEN_TENANT_ORG-D5DF>" -d '{"ownerId":"attacker","tenantId":"ORG-D5DF"}'
# Vulnerable: ownership transferred
```

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
