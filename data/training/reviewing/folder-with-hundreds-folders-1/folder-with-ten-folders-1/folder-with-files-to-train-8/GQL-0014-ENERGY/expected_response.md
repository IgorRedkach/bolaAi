## System

- System: PowerGrid Customer Billing API v1.6.0
- Domain: ENERGY / UTILITIES / SMART GRID
- Example ID: GQL-0014
- Risk ID: RISK-GQL-014

## Findings

### 1. BOLA on `getMeter` — Missing `tenant_id` Filter (RISK-GQL-014)

**Primary HAR attack**: The HAR shows `getMeter(id: "M-2014")` from JWT `tenant-3061` returning a meter belonging to `tenant-d34b`. Section 4.0 (RISK-GQL-014) confirms: `getMeter` fetches by `meterId` without verifying the fetched object's `tenantId` against the JWT.

**HAR evidence**: JWT `x-tenant-id: tenant-3061`. Request: `getMeter(id: "M-2014")`. Response: HTTP 200 OK with `"tenantId": "tenant-d34b"`, `"sensitiveField": "CONFIDENTIAL-3061d34b"`, `"internalNotes": "Internal data exposed"` — a cross-tenant smart meter record including internal grid notes returned to an unauthorized energy retailer.

**Energy/smart grid impact**: `Meter` objects include `readings: [Reading!]` which represent energy consumption measurements. Cross-tenant read access exposes a competitor utility's customer billing data and consumption patterns.

### 2. Pattern 4.2 — Persistence Poisoning via Lifecycle Actions

Section 5.0 describes Pattern 4.2 (Integrity — Persistence Poisoning): because `getMeter` lacks tenant enforcement (RISK-GQL-014), `updateMeter` and `deleteMeter` operate on the same vulnerable resolver path and also lack cross-tenant checks. This enables:

- **`updateMeter`**: inject falsified meter readings, tamper with billing status, or alter the `ownerId` — falsifying energy consumption records constitutes billing fraud and undermines grid metering integrity
- **`deleteMeter`**: destroy another tenant's meter records via `deleteMeter(id: "M-2014")` — erasing SCADA-linked billing history could disrupt energy settlement and violate regulatory metering audit requirements

### 3. BOLA on `bulkMeterLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkMeterLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `meterId` only — no `tenantId` in the cache key. Cached meter readings without a tenant dimension could poison billing computations.

## Evidence

- **HAR**: `getMeter(id: "M-2014")` with `tenant-3061` JWT → HTTP 200 → `tenantId: tenant-d34b` with `sensitiveField`.
- **Section 5.0**: Pattern 4.2 — lifecycle actions (`updateMeter`, `deleteMeter`) on unguarded resolver enable persistence poisoning.
- **Section 4.0 (RISK-GQL-014)**: `getMeter` lacks tenant check.
- **Section 4.0**: `bulkMeterLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `meterId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getMeter(id: "M-1014") { meterId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-3061"`.

**Step 2 — Cross-tenant meter read (primary HAR attack):**

```graphql
query { getMeter(id: "M-2014") { meterId tenantId ownerId data { sensitiveField internalNotes } readings { timestamp kwh } } }
```

Expected secure: HTTP 403/404 or null with authorization error.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-d34b"` and full billing meter data.

**Step 3 — Persistence poisoning — tamper with meter readings (Pattern 4.2):**

```graphql
mutation {
  updateMeter(id: "M-2014", input: {
    status: "tampered",
    data: { internalNotes: "readings_overwritten" }
  }) {
    meterId status tenantId
  }
}
```

Expected secure: Mutation rejected — cross-tenant meter access blocked.  
Expected vulnerable: HTTP 200 — meter `M-2014` belonging to `tenant-d34b` is modified by `tenant-3061`, corrupting the energy utility's billing records.

**Step 4 — Persistence poisoning — destroy meter records (Pattern 4.2):**

```graphql
mutation {
  deleteMeter(id: "M-2014")
}
```

Expected secure: Deletion rejected — cross-tenant access blocked.  
Expected vulnerable: `true` — competitor's meter billing history permanently destroyed.

**Step 5 — Bulk cross-tenant meter lookup:**

```graphql
mutation { bulkMeterLookup(ids: ["M-2014", "M-3014", "M-4014"]) { meterId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in `getMeter`** (RISK-GQL-014).
- **Enforce cross-tenant check before `updateMeter` and `deleteMeter`**: verify `meter.tenantId == jwt.tenantId` before any write or delete.
- **Immutable audit log for meter readings**: meter readings must be append-only with cryptographic integrity for regulatory compliance.
- **Filter `bulkMeterLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
