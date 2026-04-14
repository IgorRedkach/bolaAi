# Expected Response

## System
- **Domain:** Financial Services / Open Banking
- **System:** NexaBank Open Finance API
- **Example ID:** GQL-0202

## Priority Findings

### Finding 1: Open Banking — BOLA via listAccounts Multi-Tenant Access Exposes Cross-Tenant Account Data (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access

**Summary:**
Per §4.0 (RISK-GQL-202): The `getAccount` resolver fetches by `accountId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.5 — multi-tenant/cross-tenant access): the `listAccounts` endpoint accepts a caller-supplied `tenantId` without JWT validation, returning financial accounts belonging to other tenants. An attacker from `tenant-99f3` queried `listAccounts(tenantId: "tenant-4b01")` and received account records belonging to `tenant-4b01`, including `CONFIDENTIAL-99f34b01`. In Financial Services / Open Banking, unauthorized access to account balances, transaction histories, and financial positions constitutes a serious PSD2/banking regulation violation and fraud enablement.

**Evidence from HAR:**
- Request: `POST https://api.nexabank-open-financ.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-99f3`
- Query: `listAccounts(tenantId: "tenant-4b01") { accountId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-4b01"`, `ownerId: "other-user-99f34b01"`, `sensitiveField: "CONFIDENTIAL-99f34b01"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-99f34b01`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-202 | getAccount resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.5 | Multi-tenant cross-tenant access via caller-supplied tenantId |
| HAR query | tenantId: "tenant-4b01" | Injected cross-tenant account filter |
| HAR response | tenantId | tenant-4b01 returned to tenant-99f3 |
| HAR response | sensitiveField | CONFIDENTIAL-99f34b01 |
| HAR header | x-request-id | req-99f34b01 |

## Steps to Reproduce

### Step 1 — listAccounts multi-tenant BOLA open banking (HAR)
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-99f3" \
  -d '{"query": "query { listAccounts(tenantId: \"tenant-4b01\") { accountId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-4b01` account records including `CONFIDENTIAL-99f34b01`. **Secure:** FORBIDDEN — `tenantId` from JWT; only `tenant-99f3` accounts returned.

## Remediation
1. Ignore caller-supplied `tenantId`; enforce `WHERE tenant_id = $jwt.tenantId` in resolver.
2. Apply PSD2 Strong Customer Authentication (SCA) before any account data access.
3. Redis cache key: `account:{tenantId}:{accountId}`.
