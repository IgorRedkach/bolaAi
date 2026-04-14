## System

- System: LearnPath Assessment Platform v1.0.8
- Domain: EDUCATION / EDTECH LMS
- Example ID: GQL-0416
- Risk ID: RISK-GQL-416

## Findings

### 1. Pattern 10.1 — ID Swap in Own Request via `getResource` (HAR Primary)

**HAR evidence**: JWT `x-tenant-id: tenant-1a78`. Request: `getResource(id: "R-2416")`. Response: HTTP 200 OK with `"tenantId": "tenant-3913"`, `"sensitiveField": "CONFIDENTIAL-1a783913"`, `"internalNotes": "Internal data exposed"`.

**Pattern 10.1 (Single-User — ID Swap)**: a single authenticated user with one token substitutes their own valid `resourceId` with a victim institution's `resourceId`. No other change is required — one ID substitution in the GraphQL argument is sufficient to return another institution's assessment data.

**Education/EdTech impact**: `Resource` objects in an assessment platform represent courses, exams, or content modules with `items: [Item!]` as questions and student submissions. Single-token cross-tenant access exposes exam questions, answer keys, and grade data from a competing institution (`tenant-3913`) — constituting academic IP theft and FERPA violation.

### 2. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter

Section 4.0: documented gap — `bulkResourceLookup` accepts arbitrary IDs without per-ID filtering.

### 3. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `resourceId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `getResource(id: "R-2416")` with `tenant-1a78` JWT → HTTP 200 → `tenantId: tenant-3913` with `sensitiveField`.
- **Section 5.0**: Pattern 10.1 — single user swaps own `resourceId` with victim's using one token.
- **Section 4.0 (RISK-GQL-416)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1416") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-1a78"`.

**Step 2 — Single-token ID swap: access cross-tenant assessment resource (primary HAR attack):**

```graphql
query { getResource(id: "R-2416") { resourceId tenantId ownerId data { sensitiveField internalNotes } items { itemId } } }
```

Replace own ID with victim's ID — no other change. Expected secure: HTTP 403/404 or null.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-3913"` and full assessment resource data.

**Step 3 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2416", "R-3416", "R-4416"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-416).
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
