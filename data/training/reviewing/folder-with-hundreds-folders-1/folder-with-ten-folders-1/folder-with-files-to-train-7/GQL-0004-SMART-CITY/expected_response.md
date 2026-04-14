## System

- System: MetroPulse Traffic Orchestration v3.3.0
- Domain: SMART CITY / TRAFFIC MANAGEMENT
- Example ID: GQL-0004
- Risk ID: RISK-GQL-004

## Findings

### 1. BOLA on `listIntersections` — Client-Controlled `tenantId` Argument Trusted Over JWT (Pattern 1.5)

The HAR shows `listIntersections(tenantId: "tenant-0c3e")` with JWT `tenant-b0b0`. Section 5.0: "The resolver trusts the client-supplied `tenantId` instead of extracting it from the JWT." The attacker enumerates all intersection nodes for a foreign city operator by overriding the tenant scope in the query argument.

**HAR evidence**: JWT `x-tenant-id: tenant-b0b0`. Request: `listIntersections(tenantId: "tenant-0c3e")`. Response: HTTP 200 OK. Response `"tenantId": "tenant-0c3e"` with `"sensitiveField": "CONFIDENTIAL-b0b00c3e"` — intersection control data for `tenant-0c3e` returned to `tenant-b0b0`.

**Safety impact**: `Intersection` type includes `commands: [Command!]`. An attacker enumerating intersection topology can follow up with `updateIntersection` BOLA to issue unauthorized traffic signal commands.

### 2. BOLA on `getIntersection` — Missing `tenant_id` Filter (Pattern 1.1, RISK-GQL-004)

Section 4.0 (RISK-GQL-004): `getIntersection` resolver fetches by `nodeId` only — no `tenantId` check.

### 3. BOLA on `bulkIntersectionLookup` — No Per-ID Tenant Filter (Pattern 1.9)

Section 4.0: "The `bulkIntersectionLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering."

### 4. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `nodeId` (NOTE: no user dimension in cache key)."

## Evidence

- **HAR**: `listIntersections(tenantId: "tenant-0c3e")` with `tenant-b0b0` JWT → HTTP 200 → `tenantId: tenant-0c3e` with `sensitiveField`.
- **Section 5.0**: resolver trusts client-supplied `tenantId`.
- **Section 4.0 (RISK-GQL-004)**: `getIntersection` lacks tenant check.
- **Section 4.0**: `bulkIntersectionLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `nodeId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getIntersection(id: "N-1004") { nodeId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-b0b0"`.

**Step 2 — `listIntersections` tenant override (primary HAR attack):**

```graphql
query { listIntersections(tenantId: "tenant-0c3e") { nodeId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: results restricted to authenticated user's tenant.  
Expected vulnerable outcome: HTTP 200 with `tenant-0c3e` intersection list.

**Step 3 — Single cross-tenant node lookup:**

```graphql
query { getIntersection(id: "N-2004") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"getIntersection": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-0c3e"`.

**Step 4 — Bulk node lookup:**

```graphql
mutation { bulkIntersectionLookup(ids: ["N-2004", "N-3004", "N-4004"]) { nodeId tenantId data { sensitiveField } } }
```

Expected secure outcome: only `tenant-b0b0` nodes returned.  
Expected vulnerable outcome: cross-tenant intersection nodes returned.

## Remediation

- **Ignore client-supplied `tenantId` in `listIntersections`**: always extract from JWT.
- **Enforce `tenant_id` in `getIntersection` resolver** (RISK-GQL-004): `WHERE nodeId = $id AND tenant_id = $jwtTenantId`.
- **Filter `bulkIntersectionLookup` results**: exclude records where `tenant_id != jwtTenantId`.
- **Add `tenantId` to Redis cache key**.
- **Scope `updateIntersection` mutations to JWT tenant** to prevent follow-on traffic command injection.
