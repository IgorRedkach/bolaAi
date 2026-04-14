# Expected Response

## System
- Domain: Legal Tech / Document Management
- System: LexVault eDiscovery API
- Example ID: GQL-0124

## Priority Findings

### Finding 1: Legal Tech eDiscovery — Bulk Lookup Enables Persistence Poisoning via Lifecycle Actions (Pattern 4.2)
**Severity:** Critical
**Category:** Integrity / Persistence Poisoning via Lifecycle Actions

**Summary:**
Per §4.0 RISK-GQL-124 and §5.0 (Pattern 4.2 — persistence poisoning via lifecycle actions): The `bulkResourceLookup` resolver accepts an arbitrary array of document IDs without enforcing tenancy. An attacker from `tenant-bfc3` queried `bulkResourceLookup(ids: ["R-2124", "R-1124", "R-3124"])` against eDiscovery documents belonging to `tenant-2fb9`, receiving `CONFIDENTIAL-bfc32fb9`. In Legal Tech / eDiscovery, unauthorized access to legal documents can constitute evidence tampering, privilege violation, and breach of legal hold obligations — exposing both parties to regulatory sanctions.

**Evidence from HAR:**
- Request: `POST https://api.lexvault-ediscovery-.example.com/graphql` (2026-04-13)
- JWT `x-tenant-id`: `tenant-bfc3`
- Query: `bulkResourceLookup(ids: ["R-2124", "R-1124", "R-3124"]) { resourceId tenantId data { sensitiveField } }`
- Response `200 OK`: `tenantId: "tenant-2fb9"`, `ownerId: "other-user-bfc32fb9"`, `sensitiveField: "CONFIDENTIAL-bfc32fb9"`, `internalNotes: "Internal data exposed"`
- `x-request-id: req-bfc32fb9`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-GQL-124 | bulkResourceLookup accepts arbitrary IDs |
| context.txt §5.0 | Pattern 4.2 | Persistence poisoning via lifecycle |
| HAR request | ids array | R-2124, R-1124, R-3124 (cross-tenant) |
| HAR response | sensitiveField | CONFIDENTIAL-bfc32fb9 |

## Steps to Reproduce

### Step 1 — Bulk eDiscovery document lookup (HAR)
```bash
curl -s -X POST https://api.lexvault-ediscovery-.example.com/graphql \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3Jfe3VpZH0iLCJyb2xlIjoie3JvbGV9IiwidGVuYW50X2lkIjoie3RlbmFudH0ifQ.SIG" \
  -H "Content-Type: application/json" -H "x-tenant-id: tenant-bfc3" \
  -d '{"query": "query { bulkResourceLookup(ids: [\"R-2124\", \"R-1124\", \"R-3124\"]) { resourceId tenantId data { sensitiveField } } }"}'
```
**Vulnerable:** `tenant-2fb9` eDiscovery documents returned. **Secure:** Only `tenant-bfc3` documents or FORBIDDEN.

## Remediation
1. `bulkResourceLookup`: `WHERE resource_id = ANY($ids) AND tenant_id = $jwt.tenantId`.
2. Lifecycle state validation: only include documents in active hold for caller's tenant.
3. Audit log every bulk access with `x-request-id` for legal chain-of-custody.
4. Redis cache key: `resource:{tenantId}:{resourceId}`.
