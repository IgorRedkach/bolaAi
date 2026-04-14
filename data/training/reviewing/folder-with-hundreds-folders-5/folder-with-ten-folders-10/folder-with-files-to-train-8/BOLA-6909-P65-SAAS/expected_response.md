# Expected Response

## System
- Domain: SaaS / Project Management
- System: TaskFlow Collaboration API
- Example ID: BOLA-6909

## Priority Findings

### Finding 1: Shadow AI and ungoverned ML endpoints (Pattern 6.5)
**Severity:** Critical
**Category:** Misconfiguration

**Summary:**
The `/api/v1/resources` endpoint is vulnerable to Pattern 6.5 (Shadow AI and ungoverned ML endpoints).
An authenticated user from `ORG-D54A` can access or modify objects owned by `ORG-AC8C`
by manipulating the resource identifier in the request.

**Evidence from artifact:**
- Request JWT `tenantId`: `ORG-D54A`
- Response body `tenantId`: `ORG-AC8C` — confirms cross-tenant data returned
- HTTP status: 200 — no authorization failure
- `sensitiveData` field exposed across tenant boundary

**Root Cause:**
Database query does not include `WHERE owner_id = $authenticatedUserId AND tenant_id = $jwtTenantId`.
The application trusts the path parameter alone.

## Steps to Reproduce

### Step 1 — Authorize baseline
```bash
curl -s "https://api.taskflow-collab.example.com/api/v1/resources/RES-7909" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D54A>"
```
Expected: Returns own record with `tenantId: "ORG-D54A"`.

### Step 2 — ID substitution
```bash
curl -s "https://api.taskflow-collab.example.com/api/v1/resources/RES-8909" \
  -H "Authorization: Bearer <TOKEN_TENANT_ORG-D54A>"
```
**Vulnerable:** Returns `tenantId: "ORG-AC8C"` and `sensitiveData`.
**Secure:** HTTP 403 or 404.

### Step 3 — Variant tests based on Pattern 6.5
No specific variant documented for Pattern 6.5 — use Steps 1-2.

## Remediation
1. Add `WHERE tenant_id = $jwt_tenant_id AND owner_id = $jwt_sub` to all queries that accept user-supplied IDs.
2. Centralise authorization middleware: never allow ID resolution without ownership check.
3. Use non-sequential, randomly-generated UUIDs for object IDs to reduce enumeration risk.
4. Add regression test: Tenant A token requests Tenant B ID — assert 403/404.
