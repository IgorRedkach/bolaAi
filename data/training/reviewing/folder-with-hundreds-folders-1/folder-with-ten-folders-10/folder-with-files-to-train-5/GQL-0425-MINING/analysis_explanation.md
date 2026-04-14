# Analysis Explanation — GQL-0425-MINING

## Changes Made

### 1. context.txt — Removed Pattern Labels
- Section 5.0 "Vulnerability Context" renamed to "Behavioral Notes"; removed "**Pattern:** 1.8 — Predictable or sequential IDs" label
- Added neutral observation about sequential ID format: "Resource identifiers are formatted as `R-{sequential_number}`, assigned incrementally at record creation"
- Section 4.0 keeps RISK-GQL-425 with factual description

### 2. Pattern 1.8 Primary: Sequential Enumeration via `bulkResourceLookup`
Pattern 1.8 is "Predictable or sequential IDs." The HAR shows IDs `R-2425`, `R-1425`, `R-3425` — clearly sequential numeric pattern. The primary demonstration adds systematic enumeration (Step 3): iterating `R-2420` through `R-2428` to harvest cross-tenant records. This is the defining characteristic of Pattern 1.8 exploitability.

### 3. HAR Primary: `bulkResourceLookup`
HAR shows `bulkResourceLookup` with sequential IDs. Made this the primary finding. Note on HAR mismatch (response `getResource` vs request `bulkResourceLookup`) — same synthetic artifact as other GQL examples.

### 4. Removed Conditional Qualifiers
Original Steps 3-4 used "if Pattern 1.9 also present" and "if Pattern 6.1 also present." `bulkResourceLookup` is documented in Section 4.0. Introspection not documented. Removed conditional qualifiers; removed speculative introspection.

### 5. Added `x-tenant-id` Header and Redis Cache
HAR shows `x-tenant-id: tenant-8369`. Added to all curl commands.
Section 2.0 documents Redis cache keyed by `resourceId` only. Added as Finding 3.

### 6. Added UUID Remediation
Sequential IDs are the root enabler of Pattern 1.8. Added "Use non-sequential UUIDs for resource IDs" as specific remediation.
