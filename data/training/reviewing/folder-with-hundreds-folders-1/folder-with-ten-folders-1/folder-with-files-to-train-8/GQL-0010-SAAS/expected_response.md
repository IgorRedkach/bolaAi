## System

- System: TaskFlow Collaboration API v2.9.6
- Domain: SAAS / PROJECT MANAGEMENT
- Example ID: GQL-0010
- Risk ID: RISK-GQL-010

## Findings

### 1. BOLA on `getProject` — Missing `tenant_id` Filter (RISK-GQL-010 / Pattern 1.1)

**Primary HAR attack**: The HAR shows `getProject(id: "P-2010")` from JWT `tenant-2c0d` returning a project belonging to `tenant-673b`. Section 4.0 (RISK-GQL-010) confirms: `getProject` fetches by `projectId` without verifying the fetched object's `tenantId` against the JWT.

**HAR evidence**: JWT `x-tenant-id: tenant-2c0d`. Request: `getProject(id: "P-2010")`. Response: HTTP 200 OK with `"tenantId": "tenant-673b"`, `"sensitiveField": "CONFIDENTIAL-2c0d673b"`, `"internalNotes": "Internal data exposed"` — a cross-tenant project including internal business strategy notes returned to an unauthorized competitor tenant.

**SaaS/project management impact**: `Project` objects include `tasks: [Task!]`, `sensitiveField` and `internalNotes` in a project management platform represent proprietary product roadmaps, client deliverable timelines, and internal revenue projections. Cross-tenant access constitutes corporate espionage.

### 2. Mass Assignment on `updateProject` — Client-Controlled `ownerId` and `tenantId` (Pattern 1.12)

Section 5.0 describes Pattern 1.12: `updateProject` accepts `ownerId` and `tenantId` as writable fields in the mutation input. An attacker can:
- Read a cross-tenant project via `getProject` (RISK-GQL-010)
- Reassign that project's `ownerId` and `tenantId` to themselves via `updateProject`

This enables full ownership transfer of a competitor's project, including all associated tasks and data, without any server-side constraint preventing these field updates.

### 3. BOLA on `bulkProjectLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkProjectLookup` accepts arbitrary IDs without per-ID filtering.

### 4. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `projectId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `getProject(id: "P-2010")` with `tenant-2c0d` JWT → HTTP 200 → `tenantId: tenant-673b` with `sensitiveField`.
- **Section 5.0**: Pattern 1.12 — `updateProject` accepts `ownerId` and `tenantId` in mutation input.
- **Section 4.0 (RISK-GQL-010)**: `getProject` lacks tenant check.
- **Section 4.0**: `bulkProjectLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `projectId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getProject(id: "P-1010") { projectId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-2c0d"`.

**Step 2 — Cross-tenant single project lookup (primary HAR attack):**

```graphql
query { getProject(id: "P-2010") { projectId tenantId ownerId data { sensitiveField internalNotes } tasks { taskId } } }
```

Expected secure: HTTP 403/404 or null with authorization error.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-673b"` and full project data.

**Step 3 — Mass assignment — transfer ownership of cross-tenant project (Pattern 1.12):**

```graphql
mutation {
  updateProject(id: "P-2010", input: {
    ownerId: "attacker-user-2c0d",
    tenantId: "tenant-2c0d"
  }) {
    projectId tenantId ownerId
  }
}
```

Expected secure: Mutation rejected — `ownerId` and `tenantId` are not user-settable, and cross-tenant ID access is blocked.  
Expected vulnerable: HTTP 200 with `tenantId: "tenant-2c0d"` — project `P-2010` now owned by the attacker.

**Step 4 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkProjectLookup(ids: ["P-2010", "P-3010", "P-4010"]) { projectId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in `getProject`** (RISK-GQL-010): `WHERE projectId = $id AND tenant_id = jwt.tenantId`.
- **Strip `ownerId` and `tenantId` from `updateProject` input**: server must source these from JWT claims, never from client-supplied mutation input.
- **Filter `bulkProjectLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**: `{tenantId}:{projectId}`.
