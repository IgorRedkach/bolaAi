## System

- System: Horizon Social Graph API v5.3.1
- Domain: SOCIAL MEDIA / IDENTITY GRAPH
- Example ID: GQL-0011
- Risk ID: RISK-GQL-011

## Findings

### 1. Cross-Tenant Write via `updatePost` — Status Change and Ownership Transfer (Pattern 1.6 + HAR Evidence)

**Primary HAR attack**: The HAR shows `updatePost(id: "P-2011", input: {status: "approved", ownerId: "attacker-0aa1d0e6"})` from JWT `tenant-0aa1`. The mutation targets a post belonging to `tenant-d0e6`, attempting to change its moderation status to `"approved"` and reassign its `ownerId` to the attacker's value. Response HTTP 200 confirms the server did not reject the cross-tenant write.

**HAR evidence**: JWT `x-tenant-id: tenant-0aa1`. Request: `updatePost(id: "P-2011", input: {status: "approved", ownerId: "attacker-0aa1d0e6"})`. Response: HTTP 200 OK with `"tenantId": "tenant-d0e6"` — confirms the mutation targeted a cross-tenant object without authorization error.

**Social media/identity graph impact**: `updatePost` with a client-supplied `status: "approved"` bypasses content moderation — an attacker from one tenant can approve posts belonging to another tenant, defeating platform trust and safety controls. Combined with `ownerId` reassignment, the attacker gains attribution control over content they did not create.

### 2. Metadata/Attribute Side-Channel via `listPosts` (Pattern 2.2)

Section 5.0 describes Pattern 2.2 (BAC): `listPosts` returns partial data including `status`, `ownerId`, and other metadata even for posts the user is not authorized to fully access. This leaks the existence, moderation status, and ownership of private or restricted posts across tenants without requiring full object access.

### 3. BOLA on `getPost` — Missing `tenant_id` Filter (RISK-GQL-011)

Section 4.0 (RISK-GQL-011): `getPost` fetches by `postId` without verifying the fetched object's `tenantId`.

### 4. BOLA on `bulkPostLookup` — No Per-ID Ownership Filter (Pattern 1.9)

Section 4.0: documented gap — `bulkPostLookup` accepts arbitrary IDs without per-ID filtering.

### 5. Redis Cache Without Tenant Dimension

Section 2.0: Redis cache keyed by `postId` only — no `tenantId` in the cache key.

## Evidence

- **HAR**: `updatePost(id: "P-2011", input: {status: "approved", ownerId: "attacker-0aa1d0e6"})` with `tenant-0aa1` JWT → HTTP 200 with cross-tenant `tenantId: tenant-d0e6` in response.
- **Section 5.0**: Pattern 2.2 — `listPosts` exposes metadata for unauthorized objects.
- **Section 4.0 (RISK-GQL-011)**: `getPost` lacks tenant check.
- **Section 4.0**: `bulkPostLookup` lacks per-ID filter.
- **Section 2.0**: Redis cache keyed by `postId` only.

## Reproduction

**Step 1 — Baseline:**

```graphql
query { getPost(id: "P-1011") { postId tenantId data { sensitiveField } } }
```

Expected: `tenantId: "tenant-0aa1"`.

**Step 2 — Cross-tenant write mutation + ownership transfer (primary HAR attack):**

```graphql
mutation {
  updatePost(id: "P-2011", input: {
    status: "approved",
    ownerId: "attacker-0aa1d0e6"
  }) {
    postId tenantId status ownerId
  }
}
```

Expected secure: Mutation rejected — cross-tenant post access is blocked.  
Expected vulnerable: HTTP 200 with modified `status: "approved"` and reassigned `ownerId`, targeting `tenantId: "tenant-d0e6"`.

**Step 3 — Metadata side-channel via `listPosts` (Pattern 2.2):**

```graphql
query { listPosts(tenantId: "tenant-d0e6") { postId status ownerId data { title } } }
```

Expected secure: Only returns posts for JWT's `tenantId`.  
Expected vulnerable: Returns metadata (existence, status, ownership) for `tenant-d0e6` posts — confirms which posts exist and their moderation state before targeting them with `updatePost`.

**Step 4 — Single cross-tenant post read (RISK-GQL-011):**

```graphql
query { getPost(id: "P-2011") { postId tenantId ownerId data { sensitiveField internalNotes } } }
```

**Step 5 — Bulk cross-tenant lookup:**

```graphql
mutation { bulkPostLookup(ids: ["P-2011", "P-3011", "P-4011"]) { postId tenantId data { sensitiveField } } }
```

## Remediation

- **Enforce cross-tenant check before `updatePost`**: verify `post.tenantId == jwt.tenantId` before applying any mutation.
- **Strip `ownerId` and `status` from client-controllable inputs**: moderation status must be set through a dedicated moderation workflow with role-based access; `ownerId` must be immutable or server-controlled.
- **Ignore client-supplied `tenantId` in `listPosts`**: source from JWT claims only.
- **Enforce `tenant_id` WHERE clause in `getPost`** (RISK-GQL-011).
- **Filter `bulkPostLookup` by JWT `tenantId`**.
- **Add `tenantId` to Redis cache key**.
