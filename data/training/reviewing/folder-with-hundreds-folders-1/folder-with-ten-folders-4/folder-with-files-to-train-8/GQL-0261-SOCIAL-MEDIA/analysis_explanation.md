# Analysis Explanation
**Folder:** GQL-0261-SOCIAL-MEDIA | **Context source:** This folder's context.txt only.

## Key Analysis Points

### Architecture
Horizon Social Graph API, GraphQL at `https://api.horizon-social-graph.example.com/graphql`. Schema: `Post` type with `postId`. Includes `updatePost(id: ID!, input: PostInput!)` mutation.

### Pattern 9.1 — GraphQL Single-Endpoint Vulnerabilities
The single `/graphql` endpoint handles all operations — queries and mutations — through the same authorization layer. The mutation resolver accepts `ownerId` as a client-supplied field, enabling cross-tenant ownership hijacking. This is a platform-level vulnerability specific to GraphQL's single-endpoint design where all mutation inputs are processed without field-level restrictions.

### HAR (§6.0) — Write Operation
- Host: `api.horizon-social-graph.example.com`, JWT, `x-tenant-id: tenant-4265`
- Request: `updatePost(id: "P-2261", input: {status: "approved", ownerId: "attacker-426526d4"})` — a **write mutation** on a victim tenant's post
- `x-request-id: req-426526d4` is a **response header** only
- HAR inconsistency: `updatePost` mutation in request but response key is `getPost` — documented as-is
- Response confirms mutation accepted: `tenantId: tenant-26d4`, `ownerId: other-user-426526d4`, `CONFIDENTIAL-426526d4`
- RISK-GQL-261

**Consistency Guard:** system `Horizon Social Graph API`, host `api.horizon-social-graph.example.com`, tenants `tenant-4265`/`tenant-26d4`, post ID `P-2261`, `ownerId: attacker-426526d4`, `CONFIDENTIAL-426526d4`, RISK-GQL-261, Pattern 9.1 — from this folder's context.txt only.
