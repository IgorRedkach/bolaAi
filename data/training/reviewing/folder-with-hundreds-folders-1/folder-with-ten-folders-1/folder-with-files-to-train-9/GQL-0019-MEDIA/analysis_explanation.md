## Analysis reasoning

1. **HAR shows `updateResource` write mutation as primary**: HAR is `updateResource(id: "R-2019", input: {status: "approved", ownerId: "attacker-a0c15440"})`. The original expected_response.md ignored this and started with a read step.

2. **Pattern 9.1 (GraphQL Single Endpoint) framing is the key training signal**: REST APIs protect write operations by routing to different HTTP methods (GET vs POST/PUT/PATCH/DELETE) or different paths, allowing path-based authorization middleware. GraphQL routes everything through `POST /graphql`. This means: (a) a WAF rule blocking DELETE on a specific path is useless — the delete comes as a POST body; (b) per-operation authorization must be at the resolver level, not HTTP middleware. The training signal is that a single missing resolver check exposes ALL operations (read, write, delete) simultaneously, not just one HTTP method.

3. **`deleteResource` step added**: section 5.0 says "all operations (including sensitive mutations)" — demonstrating a delete at the single endpoint reinforces the Pattern 9.1 concept. In a VOD platform, deleting a competitor's content is a clear sabotage scenario.

4. **Media/VOD context**: content status transitions (draft → approved → published) are business-critical in a streaming platform. Unauthorized approval bypasses content moderation gates; ownership transfer enables content rights fraud.

5. **Bulk lookup confirmed, not conditional**: section 4.0 documents `bulkResourceLookup` lacking per-ID filter.

6. **Introspection removed**: not documented in sections 4.0 or 5.0.

7. **HAR response/request mismatch**: request is `updateResource` mutation but response is `getResource`. Same synthetic artifact. Confirmed signal: `tenantId: tenant-5440` with HTTP 200.
