# Analysis Explanation — GQL-0422-AGRICULTURE

## Changes Made

### 1. Primary Pattern: Client-Controlled `tenantId` in `listResources`
Section 5.0 of context.txt explicitly states: "The API accepts `tenantId` as a filter argument. The resolver trusts the client-supplied `tenantId` instead of extracting it from the JWT. Token from `tenant-b1a1` passes `tenantId: 'tenant-ee03'` to access cross-tenant data." This is the defining characteristic of Pattern 1.5 in this example. The original `expected_response.md` did not demonstrate this at all. Added `listResources(tenantId: "tenant-ee03")` as the primary pattern attack (Step 2 in reproduction).

### 2. HAR Primary: `bulkResourceLookup`
HAR shows a `bulkResourceLookup` mutation from `tenant-b1a1` with IDs `["R-2422", "R-1422", "R-3422"]`. The response contains `getResource` data for `tenant-ee03` — the same synthetic mismatch present in other GQL examples (HAR response wrapper differs from request operation type; the cross-tenant `tenantId` in the response is the authoritative evidence of the bypass). Made this Step 3 (HAR primary).

### 3. Removed Speculative Introspection
Original Step 4 used "if Pattern 6.1 also present" qualifier for introspection. Pattern 6.1 is not documented in this context's Section 5.0 or known architectural notes. Removed.

### 4. Removed Conditional Qualifier on `bulkResourceLookup`
Original Step 3 used "if Pattern 1.9 also present" qualifier. `bulkResourceLookup` is explicitly documented in Section 4.0 (Known Architectural Notes): "The `bulkResourceLookup` mutation accepts an arbitrary array of IDs without per-ID ownership filtering." Removed qualifier.

### 5. Added `updateResource` Cross-Tenant Mutation
Schema includes `updateResource(id, input)`. Cross-tenant write access allows attacker to corrupt precision farming data (crop/yield records, sensor calibration data). Added as Finding 4 to demonstrate write-path impact. Also noted Agriculture/Precision Farming regulatory context (EU Regulation 178/2002 food traceability).

### 6. Added Redis Cache Finding
Section 2.0 explicitly documents: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)". The original response did not address this. Added as Finding 5.

### 7. Added `x-tenant-id` Header
All curl commands now include `-H "x-tenant-id: tenant-b1a1"` matching HAR header.

### 8. System Header Corrected
Added version `v1.1.2` to system line from context.txt document version. Added `Risk ID: RISK-GQL-422` from Section 4.0.
