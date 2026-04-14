# Analysis Explanation — GQL-0419-MEDIA

## What was wrong

### 1. Speculative introspection (Step 4) removed

Original Step 4 showed GraphQL introspection with "if Pattern 6.1 also present." Pattern 6.1 (introspection) is not documented in GQL-0419 context. Pattern 1.1 is. Removed speculative step.

### 2. `bulkResourceLookup` qualifier "if Pattern 1.9 also present" removed

Section 4.0 explicitly documents: "bulkResourceLookup mutation accepts an arbitrary array of IDs without per-ID ownership filtering." This is a documented vulnerability — not a speculative "if also present." Removed the conditional qualifier and restated as a confirmed finding.

### 3. Redis cache step missing

Section 2.0 explicitly documents: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)." This is a concrete documented vulnerability. Was not in original response. Added as Step 3/Finding 3.

### 4. Minor: `x-tenant-id` header added to curl commands

Original curl commands omitted the `x-tenant-id` header that is visible in the HAR request headers. Added for completeness.

## HAR alignment

HAR primary: `getResource(id: "R-2419")` with `x-tenant-id: tenant-02b9` → HTTP 200 → `tenantId: "tenant-dd65"`, `sensitiveField`, `internalNotes`. This is Step 2 — correctly matches original. No changes to HAR alignment.
