# Analysis Explanation — GQL-0421-PHARMACEUTICAL

## What was wrong

### 1. HAR primary (`updateResource` mutation) missing from response

HAR sends `updateResource(id: "R-2421", input: {status: "approved", ownerId: "attacker-b1998d32"})`. Original response only showed `getResource` reads. Added `updateResource` as Finding 2 (HAR primary).

### 2. Pattern 1.3 (bulk/list endpoints) not demonstrated with `listResources`

Original Step 3 showed `bulkResourceLookup` as a conditional "if Pattern 1.9 also present." Pattern 1.3 is specifically about `listResources` — bulk/list endpoints that return records without proper tenant filtering. Section 5.0 explicitly documents this: "`listResources` resolver returns all objects when the `tenantId` filter is omitted or when it is supplied from the client without JWT-level validation." Made `listResources` (both without tenantId and with overridden tenantId) the primary Pattern 1.3 demonstrations.

### 3. Speculative introspection removed; Redis cache added

Original Step 4 was speculative introspection ("if Pattern 6.1 also present") — not documented in GQL-0421. Removed. Section 2.0 documents Redis cache without user dimension — added as Finding 4.

### 4. `bulkResourceLookup` conditional qualifier removed

Removed "if Pattern 1.9 also present" — it's documented in Section 4.0.

### 5. HAR request/response mismatch and `ownerId` override acknowledged

HAR input includes `ownerId: "attacker-b1998d32"` — ownership hijack attempt. HAR response shows `getResource` shape (synthetic artifact). Both noted.

## Domain context

TrialVault is a Pharmaceutical / Clinical Trials platform. Resources represent clinical trial protocols, patient data (PHI), or regulatory submission records. `listResources` without tenant filter exposes all trials across all pharmaceutical companies — industrial espionage on a massive scale. `updateResource` with `status: "approved"` on a competitor's trial record constitutes regulatory fraud (21 CFR Part 11) — potentially affecting FDA submissions and patient safety.
