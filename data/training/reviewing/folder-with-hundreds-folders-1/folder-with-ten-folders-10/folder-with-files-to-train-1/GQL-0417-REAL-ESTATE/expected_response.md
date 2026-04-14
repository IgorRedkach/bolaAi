## System

- System: EstateFlow Property API v3.4.9
- Domain: REAL ESTATE / PROPTECH
- Example ID: GQL-0417
- Risk ID: RISK-GQL-417

## Findings

### 1. Pattern 10.2 — Parameter Escalation / Session Scope Extension via `getResource` (HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-3f8d`. Request: `getResource(id: "R-2417")`. Response: HTTP 200 OK with `"tenantId": "tenant-d61a"`, `"sensitiveField": "CONFIDENTIAL-3f8dd61a"`, `"internalNotes": "Internal data exposed"`.

**Pattern 10.2 (Single-User — Parameter Escalation / Own Session Scope Extension)**: the attacker extends their session scope by substituting the `resourceId` parameter with a value outside their authorized boundary. Within a single authenticated session (`tenant-3f8d`), a single parameter change grants access to another real estate agency's property portfolio data.

**Real Estate/PropTech impact**: `Resource` objects represent property listings, deal records, or client portfolios. `sensitiveField` and `internalNotes` contain buyer qualification data, negotiation notes, or confidential deal terms. One parameter change exposes a competing agency's entire property database — constituting commercial intelligence theft.

### 2. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter

Section 4.0: documented gap — `bulkResourceLookup` accepts arbitrary IDs without per-ID filtering.

### 3. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `resourceId` only.

## Evidence

- **HAR**: `getResource(id: "R-2417")` with `tenant-3f8d` JWT → HTTP 200 → `tenantId: tenant-d61a` with `sensitiveField`.
- **Section 5.0**: Pattern 10.2 — session scope extended via `resourceId` parameter substitution.
- **Section 4.0 (RISK-GQL-417)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1417") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-3f8d"`.

**Step 2 — Parameter escalation: extend session scope to competitor's property listing (primary HAR attack):**

```graphql
query { getResource(id: "R-2417") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

Expected secure: HTTP 403/404 or null.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-d61a"` and property listing data.

**Step 3 — Bulk cross-tenant property lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2417", "R-3417", "R-4417"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-417).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
