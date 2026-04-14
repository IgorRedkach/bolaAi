## System

- System: TrialVault ClinicalOps API v2.3.4
- Domain: PHARMACEUTICAL / CLINICAL TRIALS
- Example ID: GQL-0021
- Risk ID: RISK-GQL-021

## Findings

### 1. Session Scope Extension via `bulkResourceLookup` — Foreign IDs Extend Authorized Session (Pattern 10.2 / HAR Primary)

**Primary HAR attack**: The HAR shows `bulkResourceLookup(ids: ["R-2021", "R-1021", "R-3021"])` from JWT `tenant-5274`. Pattern 10.2 (Single-User — Parameter Escalation / Own Session Scope Extension): the attacker mixes their own authorized IDs (e.g., `R-1021`) with foreign cross-tenant IDs (`R-2021`, `R-3021`) in the same bulk lookup, extending the scope of their session beyond the authorized boundary without changing their token.

**HAR evidence**: JWT `x-tenant-id: tenant-5274`. Request: `bulkResourceLookup(ids: ["R-2021", "R-1021", "R-3021"])`. Response: HTTP 200 OK with `"tenantId": "tenant-233b"` — cross-tenant clinical trial data returned alongside the attacker's own authorized records in a single response.

**21 CFR Part 11 / Pharmaceutical impact**: `Resource` objects in a clinical trials management platform represent trial protocols, case report forms, or adverse event records. Unauthorized access to another pharmaceutical company's trial data constitutes proprietary research theft. Under 21 CFR Part 11, electronic records in FDA-regulated systems require strict access controls and audit trails — cross-tenant bulk access violates both requirements.

### 2. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-021)

Section 4.0 (RISK-GQL-021): `getResource` fetches by `resourceId` without tenant check.

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Documented Gap)

Section 4.0: `bulkResourceLookup` accepts arbitrary IDs without per-ID filtering — this is the primary HAR attack vector.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key. Clinical trial records cached without tenant dimension could serve cross-pharma data.

## Evidence

- **HAR**: `bulkResourceLookup(ids: ["R-2021", "R-1021", "R-3021"])` with `tenant-5274` JWT → HTTP 200 → `tenantId: tenant-233b` with `sensitiveField`.
- **Section 5.0**: Pattern 10.2 — user extends session scope by including cross-tenant IDs in bulk parameter.
- **Section 4.0 (RISK-GQL-021)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1021") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-5274"`.

**Step 2 — Session scope extension via bulk ID list (primary HAR attack):**

```graphql
mutation {
  bulkResourceLookup(ids: ["R-2021", "R-1021", "R-3021"]) {
    resourceId tenantId ownerId
    data { sensitiveField internalNotes auditLog { event timestamp } }
    items { itemId }
  }
}
```

Mix own IDs (authorized) with foreign IDs (unauthorized). Expected secure: Only own records returned.  
Expected vulnerable: HTTP 200 with clinical trial records from `tenant-233b` alongside attacker's own records.

**Step 3 — Single cross-tenant trial record read (RISK-GQL-021):**

```graphql
query { getResource(id: "R-2021") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

## Remediation

- **Filter `bulkResourceLookup` by JWT `tenantId`**: after fetching, discard any result where `tenantId != jwt.tenantId` — the session scope must not be extensible via parameter list manipulation.
- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-021).
- **21 CFR Part 11 audit trail**: all access to clinical trial records must be logged with `sub`, `tenantId`, `resourceId`, and timestamp — cross-tenant mismatch must generate a compliance alert.
- **Add `tenantId` to Redis cache key**.
