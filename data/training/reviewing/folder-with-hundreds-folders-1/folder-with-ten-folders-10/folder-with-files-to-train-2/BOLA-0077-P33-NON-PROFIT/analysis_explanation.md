# Analysis Explanation — BOLA-0077-P33-NON-PROFIT

## What was wrong

### 1. Wrong endpoint and resource type throughout

Original response used `/api/v1/resources/RES-*`. Section 2.0 and HAR both specify `/api/v1/entitys` with `ENT-*` IDs. Fixed all reproduction steps.

### 2. Pattern 3.3 (semantic ambiguity) not explained

Original Step 3 stated "No specific variant documented for Pattern 3.3 — use Steps 1-2." Pattern 3.3 (Semantic Ambiguity — Over-Broad Endpoints) is not just a BOLA read — it's an insecure design where the endpoint's vague semantics (`entitys`) prevent meaningful authorization enforcement. The explanation must convey:
- The endpoint is over-broad: `entitys` covers multiple resource types (grant applications, donor records, beneficiary data) without type-level access controls
- The semantic ambiguity is the root design flaw: by not distinguishing between entity types, the authorization system has no basis to apply appropriate controls
- The fix is to split into type-specific endpoints with proper per-type authorization

### 3. PATCH/DELETE not demonstrated

Section 4.0 documents GET/PATCH/DELETE all use the same handler. Added PATCH (Step 3) to show grant record tampering and DELETE (Step 4) to show destruction.

### 4. Non-profit domain impact not contextualized

Added grant management context: entities represent grant applications, donor records, and beneficiary data. Cross-tenant access enables competitive grant intelligence gathering and grant record destruction.

## HAR alignment

HAR primary: `GET /api/v1/entitys/ENT-2077` with `ORG-3BED` JWT → HTTP 200 → `tenantId: "ORG-8B7E"` with `sensitiveData`. This is Step 2. Endpoint and ID format corrected.
