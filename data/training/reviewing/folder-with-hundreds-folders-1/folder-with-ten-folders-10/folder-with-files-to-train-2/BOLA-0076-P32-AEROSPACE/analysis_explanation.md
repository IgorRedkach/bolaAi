# Analysis Explanation — BOLA-0076-P32-AEROSPACE

## What was wrong

### 1. Wrong endpoint, resource type, and ID format throughout

Original response used `/api/v1/resources/RES-*`. Section 2.0 and HAR both specify `/api/v1/nodes` with `NOD-*` IDs. Fixed all reproduction steps.

### 2. HAR primary (PATCH) was replaced with GET

The HAR captures `PATCH /api/v1/nodes/NOD-2076` — a cross-tenant write operation. The original response only showed GET requests (Steps 1-2). Rewrote to make PATCH the primary Step 2.

### 3. Pattern 3.2 (workflow decoupling) not demonstrated

Original Step 3 stated "No specific variant documented for Pattern 3.2 — use Steps 1-2." This completely misses the documented Pattern 3.2 exploitation.

Section 4.0 explicitly documents the workflow bypass: "`POST /api/v1/nodes/:id/submit` succeeds without completing the prior `/validate` step." Pattern 3.2 (Workflow Decoupling — Insecure Design) is specifically about bypassing mandatory multi-step workflow sequences. In Aerospace/MRO, this is critical: skipping safety validation before submitting maintenance work orders to regulatory systems violates FAA/EASA requirements and creates direct airworthiness risks. Added Step 3 demonstrating the workflow bypass.

### 4. Aerospace/MRO domain impact not articulated

Added FAA/EASA regulatory context and the specific airworthiness risk from workflow bypass on maintenance nodes.

## HAR alignment

HAR primary: `PATCH /api/v1/nodes/NOD-2076` with `ORG-E549` JWT → HTTP 200 → `tenantId: "ORG-62CB"` with `sensitiveData`. This is Step 2. Endpoint, resource type, and ID format corrected.
