# Analysis Explanation — GQL-0428-CONSTRUCTION

## Changes Made

### 1. context.txt — Removed Pattern Label, Added Input Field Detail
Section 5.0 renamed to "Behavioral Notes"; removed "**Pattern:** 1.12 — Mass assignment via object fields." Added neutral description: `updateResource` accepts `ownerId` and `tenantId` in `input`; resolver does not strip/validate these before writing.

### 2. Pattern 1.12 Primary: `updateResource` with `ownerId`/`tenantId` mass assignment
Pattern 1.12 "mass assignment via object fields" — the specific mechanism is `updateResource` accepting ownership fields that the client can set arbitrarily. Made this the primary Pattern 1.12 demonstration (Step 2): overwrite `ownerId` and `tenantId` on a cross-tenant BIM model resource.

### 3. HAR Primary: `bulkResourceLookup`
HAR shows `bulkResourceLookup` as the HAR capture. Kept as Step 3 to show the initial cross-tenant access.

### 4. Removed Conditional Qualifiers and Introspection
Original Steps 3-4 used "if Pattern 1.9 also present" and "if Pattern 6.1 also present." `bulkResourceLookup` is documented in Section 4.0. Removed conditional qualifiers; removed speculative introspection.

### 5. Added x-tenant-id Header and Redis Cache
HAR shows `x-tenant-id: tenant-4498`. Added to all curl commands.
Added Redis cache as Finding 2.

### 6. Mass Assignment Remediation
Specific to Pattern 1.12: strip `ownerId` and `tenantId` from `updateResource` input type — server must derive these from JWT, never accept from client.

### 7. Construction/BIM Domain Context
BIM model ownership takeover via mass assignment = competitor stealing construction IP, structural design data, and project plans.
