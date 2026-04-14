# Expected Response

## System
- **Domain:** Blockchain / Decentralized Finance
- **System:** ChainVault DeFi API
- **Example ID:** GQL-0185

## Priority Findings

### Finding 1: DeFi Platform — BOLA via Cross-Service Identity Drift in listResources Exposes Cross-Tenant Vault Data (Pattern 1.10)
**Severity:** High
**Category:** BOLA / Cross-Service Identity Propagation Drift

**Summary:**
Per §4.0 (RISK-GQL-185): The `getResource` resolver fetches by `resourceId` only, without verifying `tenantId` ownership. Per §5.0 (Pattern 1.10 — cross-service identity propagation drift): the `listResources` endpoint accepts a caller-supplied `tenantId` that is not re-validated against the JWT as it propagates across internal microservices, allowing cross-tenant DeFi vault data access. An attacker from `tenant-c1b7` queried `listResources(tenantId: "tenant-eea1")` and received vault records belonging to `tenant-eea1`, including `CONFIDENTIAL-c1b7eea1`. In Blockchain / DeFi, unauthorized access to vault balances, transaction histories, and smart contract state constitutes a critical financial security incident.

**Evidence from HAR:**
- Request: `POST https://api.chainvault-defi-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-c1b7`
- Query: `listResources(tenantId: "tenant-eea1") { resourceId ownerId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-eea1"`, `ownerId: "other-user-c1b7eea1"`, `sensitiveField: "CONFIDENTIAL-c1b7eea1"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-c1b7eea1`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-185 | getResource resolver lacks tenantId ownership check |
| context.txt §5.0 | Pattern 1.10 | Cross-service identity drift — tenantId not re-validated downstream |
| HAR query | tenantId: "tenant-eea1" | Caller-injected cross-tenant DeFi vault filter |
| HAR response | tenantId | tenant-eea1 returned to tenant-c1b7 |
| HAR response | sensitiveField | CONFIDENTIAL-c1b7eea1 |
| HAR header | x-request-id | req-c1b7eea1 |

## Steps to Reproduce

### Step 1 — listResources cross-service identity drift (HAR)
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-c1b7" \
  -d '{"query": "query { listResources(tenantId: \"tenant-eea1\") { resourceId ownerId data { sensitiveField } } }"}'
```
**Vulnerable:** Returns `tenant-eea1` DeFi vault records including `CONFIDENTIAL-c1b7eea1`. **Secure:** FORBIDDEN — `tenantId` sourced from JWT only; only `tenant-c1b7` data returned.

## Remediation
1. Ignore caller-supplied `tenantId`; each microservice must independently validate `tenant_id = $jwt.tenantId`.
2. Pass JWT through inter-service calls; never accept `tenantId` from request body as authoritative.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
