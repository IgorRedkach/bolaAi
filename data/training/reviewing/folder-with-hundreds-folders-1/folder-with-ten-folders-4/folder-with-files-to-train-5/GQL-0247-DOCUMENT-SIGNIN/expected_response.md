# Security Analysis Report
**System:** SignFlow eSign Platform (Document Signing / eSign)
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** GQL-0247 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.6 | Write operation without ownership check — cross-tenant `updateResource` approves and hijacks victim's eSign document |

---

## Finding 1 — Cross-Tenant Write: eSign Document Approval Hijack (CRITICAL)

### Summary
The `updateResource` resolver on SignFlow eSign Platform (`api.signflow-esign-platf.example.com`) applies write mutations without JWT `tenantId` ownership validation (§4.0 RISK-GQL-247). Per §5.0 Pattern 1.6, write operations without ownership checks are particularly dangerous: an attacker from `tenant-5317` approves document `R-2247` belonging to `tenant-cfb4`, setting `status: "approved"` and injecting `ownerId: "attacker-5317cfb4"`. In eSign platforms, this can forge approval of legally binding documents.

**Pattern:** 1.6 — Write operations without ownership check (BOLA)
**Affected resolver:** `updateResource(id: ID!, input: ResourceInput!): Resource`
**Affected endpoint:** `POST https://api.signflow-esign-platf.example.com/graphql`

### Evidence from HAR
**Request (attacker `tenant-5317`):**
```
POST https://api.signflow-esign-platf.example.com/graphql HTTP/2.0
x-tenant-id: tenant-5317
{"query": "query VulnerableOp { updateResource(id: \"R-2247\", input: {status: \"approved\", ownerId: \"attacker-5317cfb4\"}) { resourceId status } }"}
```
**Response:** `tenantId: tenant-cfb4`, `sensitiveField: CONFIDENTIAL-5317cfb4`, `ownerId: other-user-5317cfb4`
**x-request-id:** `req-5317cfb4`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 RISK-GQL-247 | No `tenantId` check on write | Root cause | Write mutation gap |
| §5.0 Pattern 1.6 | Write BOLA | Classification | Document approval forgery |
| HAR | `R-2247` | Victim's eSign document | Cross-tenant write |
| HAR | `status: approved` | Forged approval | Legal consequence |
| HAR | `ownerId: attacker-5317cfb4` | Ownership hijack attempt | |
| HAR | `CONFIDENTIAL-5317cfb4` | Sensitive contract data | |
| HAR | `req-5317cfb4` | Correlation ID | |

### Steps to Reproduce
```bash
curl -s -X POST https://api.signflow-esign-platf.example.com/graphql \
  -H "Authorization: Bearer $ATTACKER_JWT" -H "x-tenant-id: tenant-5317" \
  -d '{"query":"mutation { updateResource(id: \"R-2247\", input: {status: \"approved\", ownerId: \"attacker-5317cfb4\"}) { resourceId tenantId data { sensitiveField } } }"}'
# VULNERABLE: approves tenant-cfb4 document, sensitiveField=CONFIDENTIAL-5317cfb4
```

### Remediation
1. Pre-mutation ownership check: `if (resource.tenantId !== context.auth.tenantId) throw ForbiddenError()`
2. Strip client-supplied `ownerId` from mutation input — server sets from JWT `sub`.
3. eSign-specific: implement cryptographic signature chain for approval actions — approval must be signed by the authenticated party, not forged via API.
4. eSign document approval is legally binding — forged approvals may constitute fraud; mandatory audit trail required.
5. Fix Redis cache key with `tenantId`.
