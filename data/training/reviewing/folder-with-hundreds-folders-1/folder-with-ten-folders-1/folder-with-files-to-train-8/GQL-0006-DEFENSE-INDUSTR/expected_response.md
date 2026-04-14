## System

- System: Aegis Vault Secure Repository v5.0.6
- Domain: DEFENSE INDUSTRIAL BASE
- Example ID: GQL-0006
- Risk ID: RISK-GQL-006

## Findings

### 1. BOLA Write — Cross-Tenant `updateResource` Without Ownership Check (Pattern 1.6 / 1.7)

The HAR shows `updateResource(id: "R-2006", input: {status: "approved", ownerId: "attacker-3785de4a"})` from JWT `tenant-3785`. The mutation targets a resource belonging to `tenant-de4a`. The attacker attempts to change the resource's `status` to `approved` and reassign `ownerId` to themselves — effectively claiming ownership of controlled defense industrial data.

**HAR evidence**: JWT `x-tenant-id: tenant-3785`. Request mutation: `updateResource(id: "R-2006", input: {status: "approved", ownerId: "attacker-3785de4a"})`. Response: HTTP 200 OK with `"tenantId": "tenant-de4a"` — the mutation was processed against a cross-tenant record. `"sensitiveField": "CONFIDENTIAL-3785de4a"` and `"internalNotes": "Internal data exposed"` returned, confirming cross-tenant write and read access.

**Defense industrial impact**: in Aegis Vault (IaC state management), `Resource` objects may represent infrastructure deployment configurations, secrets vault entries, or security clearance-scoped repositories. An attacker who approves and reassigns a foreign tenant's resource could gain custody of controlled IaC state files, API keys, or deployment credentials — potentially constituting a CMMC/ITAR violation.

### 2. BOLA on `getResource` — Missing `tenant_id` Filter (Pattern 1.1, RISK-GQL-006)

Section 4.0 (RISK-GQL-006): `getResource` resolver fetches by `resourceId` only — no tenant check.

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

### 4. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)."

## Evidence

- **HAR**: `tenant-3785` JWT → `updateResource(id: "R-2006", input: {ownerId: "attacker-3785de4a"})` → HTTP 200 → response `tenantId: tenant-de4a` with `sensitiveField` and `internalNotes`.
- **Section 4.0 (RISK-GQL-006)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1006") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-3785"` — attacker's own resource.

**Step 2 — Cross-tenant write mutation (primary HAR attack):**

```graphql
mutation { updateResource(id: "R-2006", input: { status: "approved", ownerId: "attacker-3785de4a" }) { resourceId tenantId status } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"updateResource": null}}`.  
Expected vulnerable outcome: HTTP 200 — status changed to `approved` and `ownerId` reassigned; response includes `tenantId: "tenant-de4a"` confirming cross-tenant write.

**Step 3 — Cross-tenant read:**

```graphql
query { getResource(id: "R-2006") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: forbidden or null.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-de4a"`.

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2006", "R-3006", "R-4006"]) { resourceId tenantId data { sensitiveField } } }
```

Expected vulnerable outcome: cross-tenant DIB repository data.

## Remediation

- **Enforce ownership check in `updateResource`** (RISK-GQL-006): verify `resource.tenantId == jwtTenantId` before applying mutations — reject cross-tenant updates.
- **Block `ownerId` from client-supplied mutation inputs**: `ownerId` must never be set by the client; it must be set by the server to `jwtSub` at creation time.
- **Add `tenant_id` WHERE clause to `getResource` resolver**: `WHERE resourceId = $id AND tenant_id = $jwtTenantId`.
- **Filter `bulkResourceLookup` results by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
