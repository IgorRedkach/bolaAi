## System

- System: LearnPath Assessment Platform v5.7.8
- Domain: EDUCATION / EDTECH LMS
- Example ID: GQL-0016
- Risk ID: RISK-GQL-016

## Findings

### 1. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-016)

**Primary HAR attack**: The HAR shows `getResource(id: "R-2016")` from JWT `tenant-f900` returning a resource belonging to `tenant-5d44`. Section 4.0 (RISK-GQL-016) confirms: `getResource` fetches by `resourceId` without verifying the fetched object's `tenantId` against the JWT.

**HAR evidence**: JWT `x-tenant-id: tenant-f900`. Request: `getResource(id: "R-2016")`. Response: HTTP 200 OK with `"tenantId": "tenant-5d44"`, `"sensitiveField": "CONFIDENTIAL-f9005d44"`, `"internalNotes": "Internal data exposed"` — a cross-tenant assessment resource (course, exam, or content module) returned to an unauthorized institution.

### 2. Pattern 5.2 — Resolver/Graph Traversal Injection via `getResourceWithChildren`

Section 5.0 describes Pattern 5.2 (Injection — Resolver/Graph Traversal): the GraphQL resolver chain follows nested relationships (`items: [Item!]`) without re-validating authorization at each traversal level. An attacker can call `getResourceWithChildren(id: "R-2016")` with a cross-tenant resource ID and receive the complete nested graph — including all child `Item` objects — belonging to `tenant-5d44`.

**EdTech LMS impact**: in an assessment platform, `Resource` objects represent courses or exams, and `Item` objects represent questions, answer options, student submissions, or grading rubrics. Graph traversal injection allows an attacker from one institution (`tenant-f900`) to read exam questions and student performance data from a competing institution (`tenant-5d44`) — constituting academic IP theft and FERPA violation (student educational records).

### 3. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkResourceLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `resourceId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `getResource(id: "R-2016")` with `tenant-f900` JWT → HTTP 200 → `tenantId: tenant-5d44` with `sensitiveField`.
- **Section 5.0**: Pattern 5.2 — resolver chain traverses child objects (`items`) without re-validating `tenantId` at each level.
- **Section 4.0 (RISK-GQL-016)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1016") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-f900"`.

**Step 2 — Cross-tenant resource read (primary HAR attack):**

```graphql
query { getResource(id: "R-2016") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure: HTTP 403/404 or null with authorization error.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-5d44"` and full resource data.

**Step 3 — Graph traversal injection: read parent + all child items (Pattern 5.2):**

```graphql
query {
  getResourceWithChildren(id: "R-2016") {
    resourceId tenantId
    data { sensitiveField internalNotes auditLog { event } }
    items {
      itemId
      data { sensitiveField internalNotes }
    }
  }
}
```

Expected secure: HTTP 403/404 or null — authorization re-validated at each level.  
Expected vulnerable: HTTP 200 with complete object graph for `tenant-5d44`, including all nested `Item` records (exam questions, student answers, grading notes).

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2016", "R-3016", "R-4016"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in `getResource`** (RISK-GQL-016).
- **Re-validate `tenantId` at every resolver level in `getResourceWithChildren`**: child `Item` resolvers must independently verify `WHERE tenant_id = jwt.tenantId` — do not trust the parent's authorization context.
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
