## System

- System: JobCore Candidate Portal v1.4.1
- Domain: HR TECH / TALENT ACQUISITION
- Example ID: GQL-0009
- Risk ID: RISK-GQL-009

## Findings

### 1. BOLA on `listCandidates` — Client-Controlled `tenantId` Argument (Pattern 1.10)

**Primary HAR attack**: The HAR shows `listCandidates(tenantId: "tenant-ad9d")` from JWT `tenant-4b77`. Pattern 1.10 (Cross-service identity propagation drift) describes how the JWT `tenantId` claim is not propagated through to the resolver's WHERE clause. The `listCandidates` resolver accepts a client-supplied `tenantId` argument and uses it directly instead of reading the identity from the JWT.

**HAR evidence**: JWT `x-tenant-id: tenant-4b77`. Request: `listCandidates(tenantId: "tenant-ad9d")`. Response: HTTP 200 OK with `"tenantId": "tenant-ad9d"`, `"sensitiveField": "CONFIDENTIAL-4b77ad9d"`, `"internalNotes": "Internal data exposed"` — candidate PII for a competing employer's talent pipeline returned to an unauthorized recruiter.

**HR/talent acquisition impact**: `Candidate` objects include `assessments: [Assessment!]` and `sensitiveField` which in talent acquisition platforms typically contains SSN, salary expectations, background check results, or medical screening data. Cross-tenant access allows one employer to access another employer's candidate pipeline, assessment results, and internal hiring notes — constituting a major employment law and privacy violation.

### 2. BOLA on `getCandidate` — Missing `tenant_id` Filter (RISK-GQL-009)

Section 4.0 (RISK-GQL-009): `getCandidate` resolver lacks tenant check — fetches by `candidateId` only without a `WHERE tenant_id = jwt.tenantId` predicate.

### 3. BOLA on `bulkCandidateLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkCandidateLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `candidateId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `listCandidates(tenantId: "tenant-ad9d")` with `tenant-4b77` JWT → HTTP 200 → `tenantId: tenant-ad9d` with `sensitiveField`.
- **Section 5.0**: Pattern 1.10 — `candidateId` resolver lacks ownership enforcement.
- **Section 4.0 (RISK-GQL-009)**: `getCandidate` lacks tenant check.
- **Section 4.0**: `bulkCandidateLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `candidateId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getCandidate(id: "C-1009") { candidateId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-4b77"`.

**Step 2 — `listCandidates` tenant override (primary HAR attack):**

```graphql
query { listCandidates(tenantId: "tenant-ad9d") { candidateId ownerId data { sensitiveField internalNotes } assessments { score } } }
```

Expected secure: Ignores client-supplied `tenantId`; returns only records for JWT's `tenantId`.  
Expected vulnerable: HTTP 200 with full candidate list and PII for `tenant-ad9d`.

**Step 3 — Single cross-tenant candidate lookup (RISK-GQL-009):**

```graphql
query { getCandidate(id: "C-2009") { candidateId tenantId ownerId data { sensitiveField internalNotes } } }
```

Expected secure: HTTP 403/404 or null with authorization error.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-ad9d"` and candidate PII.

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkCandidateLookup(ids: ["C-2009", "C-3009", "C-4009"]) { candidateId tenantId data { sensitiveField } } }
```

## Remediation

- **Ignore client-supplied `tenantId` in `listCandidates`**: always source `tenantId` from JWT claims — `WHERE tenant_id = jwt.tenantId`.
- **Enforce `tenant_id` WHERE clause in `getCandidate`** (RISK-GQL-009).
- **Filter `bulkCandidateLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**: `{tenantId}:{candidateId}`.
