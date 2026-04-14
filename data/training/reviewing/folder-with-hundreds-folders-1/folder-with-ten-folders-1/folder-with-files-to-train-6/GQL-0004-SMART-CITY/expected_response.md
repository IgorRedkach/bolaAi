## System

- System: MetroPulse Traffic Orchestration v3.3.0
- Domain: SMART CITY / TRAFFIC MANAGEMENT
- Example ID: GQL-0004
- Risk ID: RISK-GQL-004

## Findings

### 1. BOLA on `listIntersections` — Client-Controlled `tenantId` Filter Trusted Over JWT (Pattern 1.5)

The HAR shows the attacker sends `listIntersections(tenantId: "tenant-0c3e")` with their own JWT `tenant-b0b0`. Section 5.0 states: "The API accepts `tenantId` as a filter argument. The resolver trusts the client-supplied `tenantId` instead of extracting it from the JWT." The resolver uses the client-provided `tenantId` argument as the database filter rather than the JWT's `tenantId` claim. An attacker substitutes any target tenant's ID in the argument to receive a full intersection control listing for that municipality.

**HAR evidence**: JWT header `x-tenant-id: tenant-b0b0`. Request query: `listIntersections(tenantId: "tenant-0c3e")`. Response: HTTP 200 OK. Response `"tenantId": "tenant-0c3e"` — data belonging to a different city zone/operator returned. `"sensitiveField": "CONFIDENTIAL-b0b00c3e"` and `"internalNotes": "Internal data exposed"` confirm operational intersection data from `tenant-0c3e` served to `tenant-b0b0`.

**Safety impact**: `Intersection` objects include `commands: [Command!]`. An attacker who can enumerate intersection nodes for a foreign tenant can follow up with `updateIntersection` BOLA to issue unauthorized traffic control commands — changing signal phases or overriding managed signals — creating road safety incidents.

### 2. BOLA on `getIntersection` — Missing `tenant_id` Filter in Resolver (Pattern 1.1, RISK-GQL-004)

Section 4.0 (RISK-GQL-004): "The `getIntersection` resolver fetches by `nodeId` only. The resolver does NOT verify that the fetched object's `tenantId` matches the JWT's `tenantId`." Direct single-node lookup is also vulnerable — an attacker with a known `nodeId` can retrieve full intersection data and commands for any tenant without authorization.

### 3. BOLA on `bulkIntersectionLookup` — No Per-ID Tenant Ownership Filter (Pattern 1.9)

Section 4.0 also documents: "The `bulkIntersectionLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." An attacker can batch-lookup multiple cross-tenant `nodeId` values in a single request.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: "Redis cache keyed by `nodeId` (NOTE: no user dimension in cache key)." Cross-tenant intersection data cached without a tenant dimension can be served to any subsequent requester for that `nodeId`.

## Evidence

- **HAR trace**: JWT `x-tenant-id: tenant-b0b0` → `listIntersections(tenantId: "tenant-0c3e")` → HTTP 200 OK → response `tenantId: tenant-0c3e` with `sensitiveField` and `internalNotes`.
- **Section 5.0**: resolver trusts client-supplied `tenantId` argument rather than JWT claim.
- **Section 4.0 (RISK-GQL-004)**: `getIntersection` resolver lacks `tenantId` ownership check.
- **Section 4.0**: `bulkIntersectionLookup` lacks per-ID ownership filter.
- **Section 2.0**: Redis cache keyed by `nodeId` without tenant dimension.

## Reproduction

**Step 1 — Attacker baseline:**

```graphql
query { getIntersection(id: "N-1004") { nodeId tenantId data { sensitiveField } } }
```

Expected: returns `tenantId: "tenant-b0b0"` — attacker's own intersection node.

**Step 2 — `listIntersections` tenant override (primary HAR attack):**

```graphql
query { listIntersections(tenantId: "tenant-0c3e") { nodeId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: results restricted to authenticated user's tenant regardless of `tenantId` argument.  
Expected vulnerable outcome: HTTP 200 with full intersection list for `tenant-0c3e`, including `sensitiveField` and `internalNotes`.

**Step 3 — Single cross-tenant node lookup:**

```graphql
query { getIntersection(id: "N-2004") { nodeId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure outcome: `{"errors": [{"message": "Forbidden"}], "data": {"getIntersection": null}}`.  
Expected vulnerable outcome: HTTP 200 with `tenantId: "tenant-0c3e"` data.

**Step 4 — Bulk node lookup:**

```graphql
mutation { bulkIntersectionLookup(ids: ["N-2004", "N-3004", "N-4004"]) { nodeId tenantId data { sensitiveField } } }
```

Expected secure outcome: only `tenant-b0b0` nodes returned.  
Expected vulnerable outcome: cross-tenant intersection nodes from `tenant-0c3e` returned.

## Remediation

- **Ignore client-supplied `tenantId` in `listIntersections`**: always extract `tenantId` from the verified JWT; remove `tenantId` from the public query argument or validate it matches the JWT.
- **Enforce `tenant_id` in `getIntersection` resolver** (RISK-GQL-004): `WHERE nodeId = $id AND tenant_id = $jwtTenantId`.
- **Filter `bulkIntersectionLookup` results post-fetch**: exclude any records where `tenant_id != jwtTenantId`.
- **Add `tenantId` to Redis cache key**: change from `nodeId` to `nodeId:tenantId`.
- **Scope `updateIntersection` and command mutations to JWT tenant**: prevents follow-on traffic control command injection after enumeration.
