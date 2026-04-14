## System

- System: ClaimsFlow Underwriting API v2.6.8
- Domain: INSURANCE / CLAIMS PROCESSING
- Example ID: GQL-0012
- Risk ID: RISK-GQL-012

## Findings

### 1. BOLA on `getClaim` — Missing `tenant_id` Filter (RISK-GQL-012)

**Primary HAR attack**: The HAR shows `getClaim(id: "C-2012")` from JWT `tenant-103c` returning a claim belonging to `tenant-fb77`. Section 4.0 (RISK-GQL-012) confirms: `getClaim` fetches by `claimId` without verifying the fetched object's `tenantId` against the JWT.

**HAR evidence**: JWT `x-tenant-id: tenant-103c`. Request: `getClaim(id: "C-2012")`. Response: HTTP 200 OK with `"tenantId": "tenant-fb77"`, `"sensitiveField": "CONFIDENTIAL-103cfb77"`, `"internalNotes": "Internal data exposed"` — a cross-tenant insurance claim record including internal adjuster notes returned to an unauthorized caller.

**Insurance/claims impact**: `Claim` objects include `documents: [Document!]` and `sensitiveField` which in an underwriting platform contains policyholder PII, medical records, damage assessments, and settlement amounts. Cross-tenant access exposes HIPAA-protected health information for medical claims and enables competitor access to proprietary underwriting risk data.

### 2. Client-Assumed Authority on `updateClaim` — Status/Amount Manipulation Without Re-Validation (Pattern 3.1)

Section 5.0 describes Pattern 3.1 (Insecure Design): the `updateClaim` resolver accepts client-supplied fields including `status` (e.g., `"approved"`, `"settled"`) and financial amount fields without server-side re-validation of whether the caller has authority to apply those state changes. The server trusts client-supplied field values for business-critical decisions.

Combined with RISK-GQL-012 (no cross-tenant check), this enables:
- Reading a cross-tenant claim's current details
- Submitting `updateClaim` with `status: "approved"` to fraudulently approve a pending claim from another insurer's book of business, or deny a valid claim from a competitor's policyholder

### 3. BOLA on `bulkClaimLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkClaimLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `claimId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `getClaim(id: "C-2012")` with `tenant-103c` JWT → HTTP 200 → `tenantId: tenant-fb77` with `sensitiveField`.
- **Section 5.0**: Pattern 3.1 — `updateClaim` applies client-supplied status/amount fields without authority re-validation.
- **Section 4.0 (RISK-GQL-012)**: `getClaim` lacks tenant check.
- **Section 4.0**: `bulkClaimLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `claimId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getClaim(id: "C-1012") { claimId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-103c"`.

**Step 2 — Cross-tenant claim read (primary HAR attack):**

```graphql
query { getClaim(id: "C-2012") { claimId tenantId ownerId data { sensitiveField internalNotes } documents { docId } } }
```

Expected secure: HTTP 403/404 or null with authorization error.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-fb77"` and full claim record including adjuster notes.

**Step 3 — Client-assumed authority — fraudulent status change (Pattern 3.1):**

```graphql
mutation {
  updateClaim(id: "C-2012", input: {
    status: "approved"
  }) {
    claimId status tenantId
  }
}
```

Expected secure: Mutation rejected — either cross-tenant access blocked, or `status` is not a user-settable field without underwriter role validation.  
Expected vulnerable: HTTP 200 with `status: "approved"` — a foreign policyholder's pending claim is fraudulently approved by an attacker with no authority over that claim.

**Step 4 — Bulk cross-tenant claim lookup:**

```graphql
mutation { bulkClaimLookup(ids: ["C-2012", "C-3012", "C-4012"]) { claimId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in `getClaim`** (RISK-GQL-012).
- **Server-side authority re-validation for `updateClaim`**: `status` transitions must be gated by role and a workflow state machine — the server must not trust client-supplied status values.
- **Enforce cross-tenant check before `updateClaim`**: verify `claim.tenantId == jwt.tenantId` before applying any mutation.
- **Filter `bulkClaimLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
