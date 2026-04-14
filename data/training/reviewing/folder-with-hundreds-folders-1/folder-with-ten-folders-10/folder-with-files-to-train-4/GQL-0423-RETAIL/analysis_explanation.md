# Analysis Explanation — GQL-0423-RETAIL

## Changes Made

### 1. Pattern 1.6 Primary: `updateResource` Write Operation
Pattern 1.6 is "Write operations without ownership check." Section 5.0 explicitly states: "The `updateResource` mutation accepts an arbitrary `resourceId` without verifying the requester owns that object. A write-level BOLA allows state corruption across tenants." The original response only demonstrated a `getResource` read. Added `updateResource` as Finding 1 (primary pattern), and `deleteResource` as Finding 3, to demonstrate write-level BOLA.

### 2. HAR Primary Kept as Read
HAR shows `getResource(id: "R-2423")` read — kept as Finding 2 (HAR primary) since it is the captured evidence.

### 3. Removed Conditional Qualifier on `bulkResourceLookup`
Original Step 3 used "if Pattern 1.9 also present." `bulkResourceLookup` is explicitly documented in Section 4.0. Removed qualifier.

### 4. Removed Speculative Introspection
Original Step 4 used "if Pattern 6.1 also present." Pattern 6.1 is not documented for this example. Removed.

### 5. Added `x-tenant-id` Header
HAR shows `x-tenant-id: tenant-df1f` header. Added to all curl commands.

### 6. Added Redis Cache Finding
Section 2.0 documents: "Redis cache keyed by `resourceId` (NOTE: no user dimension in cache key)". Added as Finding 5.

### 7. Added `deleteResource`
Schema includes `deleteResource`. Cross-tenant delete allows irreversible destruction of competitor's loyalty programme records (customer points history). Added as Finding 3.

### 8. Contextualized for Retail/Loyalty Domain
Explained the specific impact: expiring a competitor's customers' loyalty points, hijacking point balances, destroying redemption history — direct business sabotage in the loyalty programme context.
