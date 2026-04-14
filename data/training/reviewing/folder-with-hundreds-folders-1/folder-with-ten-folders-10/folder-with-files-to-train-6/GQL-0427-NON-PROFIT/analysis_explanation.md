# Analysis Explanation — GQL-0427-NON-PROFIT

## Changes Made

### 1. context.txt — Removed Pattern Label, Added ownerId Propagation Note
Section 5.0 renamed to "Behavioral Notes"; removed "**Pattern:** 1.10 — Cross-service identity propagation drift." Added neutral description: client supplies `ownerId` in `updateResource` input, and this drifts into the target record. This is the key evidence for Pattern 1.10 without naming it.

### 2. Pattern 1.10 Primary: `updateResource` with ownerId propagation
HAR shows `updateResource(id: "R-2427", input: {status: "approved", ownerId: "attacker-8a02fbd5"})`. Pattern 1.10 "cross-service identity propagation drift" — the attacker's identity propagates into the cross-tenant record via the `ownerId` input field. Original had `getResource` as primary. Corrected to `updateResource` as primary (HAR authoritative).

### 3. Explained Non-Profit / Grant Management Impact
Approving another nonprofit's grant = financial fraud. Taking ownership via `ownerId` drift = claim on another organization's approved funding.

### 4. Removed Conditional Qualifiers
Original Steps 3-4 used "if Pattern 1.9 also present" and "if Pattern 6.1 also present." `bulkResourceLookup` is documented in Section 4.0. Introspection not documented. Removed conditional qualifiers; removed speculative introspection.

### 5. Added x-tenant-id Header and Redis Cache
HAR shows `x-tenant-id: tenant-8a02`. Added to all curl commands.
Added Redis cache as Finding 2 — cache poisoning post-update.

### 6. Added ownerId Strip Remediation
The specific Pattern 1.10 remediation: server must set `ownerId` from JWT `sub`, never accept it from client input in mutations.
