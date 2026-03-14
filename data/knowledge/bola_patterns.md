# BOLA Patterns and Testing Guide

## What is BOLA?

Broken Object-Level Authorization (BOLA) is when an API does not verify that the authenticated user is allowed to access or modify the specific object (by ID, key, or path) they are requesting. Attackers change object identifiers in URLs, query parameters, or request bodies to access other users' data.

## Common Patterns

### 1. ID in path without ownership check
- Endpoints like `GET /api/users/{id}`, `GET /api/patients/{id}`, `GET /api/orders/{id}` must verify that the authenticated user owns or is allowed to access that `id`.
- Test: Call with two different user tokens, change only the ID; if both return 200 and data, BOLA exists.

### 2. Related or linked resources
- A "restricted" main resource (e.g., case, ticket) may link to another table (e.g., team members, attachments) that is not restricted. Users who cannot see the main resource may still access the related data.
- Test: Enumerate or query the related resource by ID; check if authorization is enforced per object.

### 3. Bulk or list endpoints
- `GET /api/patients`, `GET /api/orders` may return all objects if the backend does not filter by current user or tenant.
- Test: Authenticate as one user and call list endpoint; verify only that user's objects are returned.

### 4. Third-party or storage APIs
- URLs or API keys that allow access to objects (e.g., images, files) without checking that the requester is allowed to see that object. Editing the URL or parameter can expose other objects.
- Test: Obtain one valid URL or ID, then change ID or path segment; check if other objects are returned.

### 5. Logs and operational visibility
- Logs, queues, or admin UIs that show full request/response data (including PII or object IDs) to operators who should not see that data. Retries and failures may re-expose the same data.
- Test: Review who can see logs and what is logged; check for object-level data in error messages or retry payloads.

### 6. Multi-tenant / cross-tenant access
- API takes an accountId, orgId, or tenantId in the path or query. The backend does not verify that the caller's token matches the requested tenant.
- Test: Use token from tenant A to request resources of tenant B (e.g. GET /api/accounts/{tenant_B_account}/data). If data is returned, cross-tenant BOLA.

### 7. Write operations (PATCH, PUT, DELETE) without ownership check
- Endpoints that modify or delete resources (PATCH /invoices/{id}, DELETE /files/{id}) may not check that the caller owns the resource.
- Test: User A creates a resource. User B calls the write endpoint with user A's resource ID. If the operation succeeds, BOLA on write.

### 8. Nested resources without parent authorization
- Endpoints like GET /projects/{projectId}/tasks/{taskId} may validate taskId under projectId but not that the caller is a project member.
- Test: User A is not a member of project X. Call GET /projects/X/tasks/1. If task is returned, nested-resource BOLA.

### 9. Predictable or sequential IDs
- When object IDs are sequential integers or easily guessable, BOLA becomes trivially exploitable via enumeration.
- Test: Note the ID of a newly created object; try ID-1 and ID+1 with a different user. If data is returned, BOLA + IDOR.

### 10. Batch/bulk lookup endpoints
- POST /batch/lookup accepts an array of IDs and returns matching objects. If no per-ID ownership filter is applied, attacker can retrieve any objects.
- Test: User B submits IDs belonging to user A in a batch request. If objects are returned, batch BOLA.

### 11. Webhook or callback endpoints
- Callback URLs (e.g. POST /webhooks/payment) accept an object ID (orderId) and update its state. If no signature or origin validation is documented, any party can forge callbacks.
- Test: Send a callback with a valid orderId but no valid signature. If state changes, BOLA on write via callback.

### 12. Admin endpoints with insufficient scope
- Admin endpoints (GET /admin/audit-log/{userId}) may check the "admin" role but not restrict which users' data the admin can see (e.g. cross-department, cross-tenant).
- Test: Admin in dept A requests audit log of user in dept B. If returned, object-level scope is missing even for admins.

### 13. GraphQL: single endpoint, BOLA in operations
- GraphQL uses one endpoint (POST /graphql). BOLA occurs in **query/mutation operations** and **field arguments**, not in the URL.
- Operations like `user(id: ID!)`, `document(id: ID!)`, `deleteOrder(id: ID!)` take object IDs. If resolvers do not check ownership, any user can access any object.
- Test: With two different user tokens, call the same query/mutation with the same object ID. If both receive data (or both succeed for mutations), BOLA.

### 14. GraphQL: nested resolvers and batch queries
- Nested fields (e.g. `User { orders { id } }`) may have resolvers that do not filter by parent ownership. User A could request User B's orders via a nested selection.
- Batch/alias queries: `{ a: user(id: "1") {...} b: user(id: "2") {...} }` can enumerate objects in one request.
- Test: As user A, request a nested field that returns objects belonging to user B (e.g. via a shared query or variable). If data is returned, nested-resolver BOLA.

### 15. SOQL and Salesforce record-level access
- SOQL queries (SELECT ... FROM Account, Case, etc.) may not enforce record-level sharing. Missing `WITH SECURITY_ENFORCED` or ownership filters (e.g. WHERE OwnerId = :userId) can expose records across users/tenants.
- Cross-object queries: `SELECT Id, (SELECT Id FROM Cases) FROM Account` — subquery Cases may not respect sharing.
- Test: Run SOQL as user A for records owned by user B. If records are returned, record-level BOLA. Check for WITH SECURITY_ENFORCED and UserRecordAccess usage.

## Verification steps (generic)

1. Identify all endpoints that take an object identifier (path, query, body).
2. For each, with two different authenticated users (or tokens), request the same object ID. If both succeed, object-level authorization is broken.
3. Check documentation for explicit "authorization" or "permission" for the object; if missing, treat as suspected BOLA.
4. For list endpoints, ensure response is filtered by tenant/user; otherwise consider it BOLA.
5. For linked resources, verify that related entities enforce the same (or stricter) access control as the parent.
6. For write operations (PATCH, PUT, DELETE), verify that the caller owns or is allowed to modify the resource.
7. For batch/bulk endpoints, verify that the response only includes objects the caller is authorized to see.
8. For callbacks/webhooks, verify signature or origin validation is documented and enforced.
9. For GraphQL: identify all operations (queries, mutations) that take object IDs as arguments. With two tokens, call the same operation with the same ID; if both succeed, BOLA. Check nested resolvers for ownership filtering.
10. For SOQL/Salesforce: verify SOQL uses WITH SECURITY_ENFORCED or explicit ownership filters. Test cross-object subqueries for record-level access. Check sharing model and UserRecordAccess where applicable.
