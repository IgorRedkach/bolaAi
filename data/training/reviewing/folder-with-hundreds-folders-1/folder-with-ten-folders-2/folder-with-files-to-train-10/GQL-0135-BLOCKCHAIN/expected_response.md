# Expected Response

## System
- Domain: Blockchain / DeFi
- System: ChainVault DeFi API
- Example ID: GQL-0135

## Priority Findings

### Finding 1: DeFi Platform — Bulk Resource Lookup Exposes Cross-Tenant Wallet and Transaction Data (Pattern 1.3)
**Severity:** Critical
**Category:** BOLA / Bulk or List Endpoints

**Summary:**
Per §5.0 (Pattern 1.3 — bulk or list endpoints): The `bulkResourceLookup` resolver accepts an arbitrary array of resource IDs without validating tenancy. An attacker from `tenant-df08` queried `bulkResourceLookup(ids: ["R-2135", "R-1135", "R-3135"])` and received DeFi platform data belonging to `tenant-81f0`, including `CONFIDENTIAL-df0881f0`. In Blockchain / DeFi, unauthorized access to wallet addresses, transaction histories, and vault configurations enables financial fraud, front-running, and targeted theft.

**Evidence from HAR:**
- Request: `POST https://api.chainvault-defi-api.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-df08`
- Query: `bulkResourceLookup(ids: ["R-2135", "R-1135", "R-3135"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-81f0"`, `ownerId: "other-user-df0881f0"`, `sensitiveField: "CONFIDENTIAL-df0881f0"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-df0881f0`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §5.0 | Pattern 1.3 | bulkResourceLookup, no tenancy filter |
| HAR request | ids array | R-2135, R-1135, R-3135 (cross-tenant) |
| HAR response | tenantId | tenant-81f0 returned for tenant-df08 caller |
| HAR response | sensitiveField | CONFIDENTIAL-df0881f0 |

## Steps to Reproduce

### Step 1 — Bulk DeFi resource lookup (HAR)
```bash
curl -s -X POST https://api.chainvault-defi-api.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-df08" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2135\", \"R-1135\", \"R-3135\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-81f0` DeFi vault data returned. **Secure:** Only `tenant-df08` data or FORBIDDEN.

## Remediation
1. Bulk lookup: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Limit bulk array size; rate-limit DeFi bulk lookups.
3. Redis cache key: `resource:{tenantId}:{resourceId}`.
4. Audit log all bulk accesses with `x-request-id` for on-chain correlation.
