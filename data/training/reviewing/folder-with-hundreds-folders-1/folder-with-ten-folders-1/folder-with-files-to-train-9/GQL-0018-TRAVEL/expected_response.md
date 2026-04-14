## System

- System: SkyPort Global Distribution v4.5.0
- Domain: TRAVEL / GDS
- Example ID: GQL-0018
- Risk ID: RISK-GQL-018

## Findings

### 1. BOLA on `bulkResourceLookup` — Batch Cross-Tenant Lookup Exposing Traveler PII (Pattern 7.1 / HAR Primary)

**Primary HAR attack**: The HAR shows `bulkResourceLookup(ids: ["R-2018", "R-1018", "R-3018"])` from JWT `tenant-50cd`. The batch lookup returns multiple cross-tenant booking records without ownership filtering.

**HAR evidence**: JWT `x-tenant-id: tenant-50cd`. Request: `bulkResourceLookup(ids: ["R-2018", "R-1018", "R-3018"])`. Response: HTTP 200 OK with `"tenantId": "tenant-8ffc"`, `"sensitiveField": "CONFIDENTIAL-50cd8ffc"`, `"internalNotes": "Internal data exposed"` — cross-tenant PNR data returned in bulk.

**Pattern 7.1 (Logging Failures — Operational PII/PHI leakage)**: the BOLA enables mass cross-tenant access to traveler PII (passenger name records, itinerary details, potentially passport numbers and payment method references). The logging failure compounds this: if cross-tenant access events are not flagged in audit logs, each unauthorized `bulkResourceLookup` call retrieves multiple airlines' or agencies' traveler records silently, with no breach detection signal.

**Travel/GDS impact**: `Resource` objects in a Global Distribution System represent booking records (PNRs) containing traveler names, itineraries, and contact information. The `auditLog: [AuditEntry!]` field means an attacker reading cross-tenant records also receives the operational audit trail of a competing carrier's bookings — revealing internal booking patterns and modification history.

### 2. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-018)

Section 4.0 (RISK-GQL-018): `getResource` fetches by `resourceId` without tenant check.

### 3. `auditLog` Field Exposure via Cross-Tenant Access

The `ResourceData` type includes `auditLog: [AuditEntry!]`. Cross-tenant access via `bulkResourceLookup` or `getResourceWithChildren` exposes the operational audit trail for another carrier's booking records — including who modified the PNR, when, and what changed.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key — cached booking records without tenant dimension.

## Evidence

- **HAR**: `bulkResourceLookup(ids: ["R-2018", "R-1018", "R-3018"])` with `tenant-50cd` JWT → HTTP 200 → `tenantId: tenant-8ffc` with `sensitiveField`.
- **Section 5.0**: Pattern 7.1 — cross-tenant access exposes PII; logging failures mean unauthorized access is not detected.
- **Section 4.0 (RISK-GQL-018)**: `getResource` lacks tenant check.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1018") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-50cd"`.

**Step 2 — Bulk cross-tenant booking record lookup (primary HAR attack):**

```graphql
mutation {
  bulkResourceLookup(ids: ["R-2018", "R-1018", "R-3018"]) {
    resourceId tenantId ownerId
    data { sensitiveField internalNotes auditLog { event timestamp } }
    items { itemId }
  }
}
```

Expected secure: Only returns records where `tenantId` matches JWT `tenantId`.  
Expected vulnerable: HTTP 200 with PNR data for multiple tenants in a single batch response, including `auditLog` entries.

**Step 3 — Single cross-tenant booking read (RISK-GQL-018):**

```graphql
query { getResource(id: "R-2018") { resourceId tenantId ownerId data { sensitiveField internalNotes auditLog { event timestamp actor } } } }
```

## Remediation

- **Filter `bulkResourceLookup` by JWT `tenantId`**: after fetching by IDs, remove any result where `tenantId != jwt.tenantId`.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-018).
- **Audit log all cross-tenant access attempts**: any request where a fetched object's `tenantId` does not match the JWT's `tenantId` must generate a security alert — the logging failure is what makes Pattern 7.1 uniquely dangerous.
- **Add `tenantId` to Redis cache key**.
