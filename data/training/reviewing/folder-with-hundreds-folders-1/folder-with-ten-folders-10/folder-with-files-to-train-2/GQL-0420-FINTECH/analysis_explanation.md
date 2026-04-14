# Analysis Explanation — GQL-0420-FINTECH

## What was wrong

### 1. HAR primary (`bulkResourceLookup`) was in Step 3 — moved to Step 2

HAR sends `bulkResourceLookup(ids: ["R-2420", "R-1420", "R-3420"])`. Original response had `getResource` as Step 2 (primary) and `bulkResourceLookup` as Step 3. Swapped to align with HAR.

### 2. HAR request/response mismatch acknowledged

HAR request sends `bulkResourceLookup` but response body shows `getResource`-shaped data. Noted as synthetic test harness artifact.

### 3. Pattern 1.2 (related/linked resources) demonstration added

Original response only showed flat ID substitution reads — not the linked resource traversal that Pattern 1.2 specifically describes. Pattern 1.2 (Related or Linked Resources) means the attacker accesses linked child resources through a parent without authorization checks on each child. `getResourceWithChildren` is the canonical Pattern 1.2 vector — it traverses from a transaction to its linked `items` (payment legs, sub-records) without per-item tenant validation. Added `getResourceWithChildren` as Finding 2.

### 4. Speculative introspection removed; Redis cache added

Original Step 4 was speculative introspection ("if Pattern 6.1 also present") — not documented in GQL-0420. Removed. Section 2.0 explicitly documents Redis cache without user dimension — added as Finding 4.

### 5. `bulkResourceLookup` conditional qualifier removed

Removed "if Pattern 1.9 also present" — `bulkResourceLookup` is documented in Section 4.0 as a confirmed vulnerability.

## Domain context

PayBridge is a Fintech / Payments Gateway. Resources represent payment transactions linked to sub-records (payment legs, settlement records, refunds). Cross-tenant `bulkResourceLookup` and `getResourceWithChildren` expose competitor transaction data — PCI DSS Requirement 7 (need-to-know) violation. Financial data exfiltration enables competitive intelligence on payment volumes, merchant relationships, and settlement timing.
