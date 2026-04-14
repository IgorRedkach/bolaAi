# Analysis Explanation — GQL-0426-AEROSPACE

## Changes Made

### 1. context.txt — Removed Pattern Label
Section 5.0 renamed from "Vulnerability Context" to "Behavioral Notes"; removed "**Pattern:** 1.9 — Batch/bulk lookup endpoints" label. Replaced with neutral description of the `bulkResourceLookup` behavior: accepts arbitrary IDs, no per-ID ownership check, returns records from multiple tenants.

### 2. Pattern 1.9 Primary: `bulkResourceLookup`
Pattern 1.9 is specifically "Batch/bulk lookup endpoints." The original response had `bulkResourceLookup` as Step 3 with conditional qualifier "if Pattern 1.9 also present" — this is inverted. Made `bulkResourceLookup` the primary finding (HAR already demonstrates it).

### 3. Removed Conditional Qualifier
Original Step 3 used "if Pattern 1.9 also present." `bulkResourceLookup` is documented in Section 4.0. Removed qualifier.

### 4. Removed Speculative Introspection
Original Step 4 used "if Pattern 6.1 also present." Not documented. Removed.

### 5. Added `x-tenant-id` Header
HAR shows `x-tenant-id: tenant-9953`. Added to all curl commands.

### 6. Added Mass Enumeration Step
Pattern 1.9's core risk is mass data harvest in a single request. Added Step 3 with a larger batch (8 IDs) showing mass enumeration of MRO records in one call.

### 7. Added Redis Cache Finding
Section 2.0 documents Redis cache keyed by `resourceId` only. Added as Finding 3.

### 8. Added Rate-Limit Remediation
Specific to bulk endpoints: rate-limiting batch size prevents mass enumeration even if ID ownership check is missed.
