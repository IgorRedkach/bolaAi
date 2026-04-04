# Security Vulnerability Patterns and Testing Guide

## Overview

This guide covers vulnerability patterns that can be identified by investigating documentation, schemas, API specs, HAR captures, and log/network traces. BOLA (Broken Object-Level Authorization) is the primary focus but all classes are in scope when evidenced by artifacts.

---

## 1. Broken Object-Level Authorization (BOLA)

BOLA occurs when an API does not verify that the authenticated user is allowed to access or modify the specific object they are requesting. Attackers change object identifiers in URLs, query parameters, or request bodies to access other users' data.

### 1.1 ID in path without ownership check
- Endpoints like `GET /api/resources/{id}` must verify the caller owns or is allowed to access that ID.
- Test: Call with two different user tokens, same ID; if both return data, BOLA exists.

### 1.2 Related or linked resources
- A restricted main resource may link to an unrestricted related table. Users locked out of the parent can still access child/linked data.
- Test: Query the related resource by parent ID with an unauthorized user.

### 1.3 Bulk or list endpoints
- List endpoints may return all objects if the backend does not filter by user or tenant.
- Test: Authenticate as one user; verify only that user's objects are returned.

### 1.4 Third-party or storage APIs
- URLs or keys allowing access to objects (images, files) without checking requester authorization.
- Test: Change the ID or path segment; check if unauthorized objects are returned.

### 1.5 Multi-tenant / cross-tenant access
- API accepts tenantId/orgId in path or query. Backend does not verify the token matches the requested tenant.
- Test: Use token from tenant A to request resources of tenant B.

### 1.6 Write operations without ownership check
- PATCH, PUT, DELETE endpoints may not verify the caller owns the resource.
- Test: User A creates resource. User B calls write endpoint with User A's resource ID.

### 1.7 Nested resources without parent authorization
- Endpoints like `/projects/{id}/tasks/{id}` may validate the child exists under the parent but not that the caller is authorized for the parent.
- Test: Call with a valid parent/child pair but an unauthorized user.

### 1.8 Predictable or sequential IDs
- Sequential integers or guessable patterns make BOLA trivially exploitable via enumeration.
- Test: Note a new object's ID; try adjacent IDs with a different user.

### 1.9 Batch/bulk lookup endpoints
- Batch endpoints accept arrays of IDs. If no per-ID ownership filter exists, any user can retrieve any objects.
- Test: Submit IDs belonging to other users in a batch request.

### 1.10 Cross-service identity propagation drift
- The caller's identity or tenant context is lost or weakened crossing internal service boundaries.
- Test: Trace a request through multiple services; verify authorization context is preserved at each hop.

### 1.11 Cache-key authorization mismatch
- Cached responses keyed by object ID alone (no user dimension) serve data across users.
- Test: Request an object as User A, then as User B; if User B gets User A's cached response, BOLA.

### 1.12 Mass assignment via object fields
- Write endpoints accept fields that override ownership, role, or status attributes.
- Test: Submit a write request with additional fields (ownerId, role, status) not shown in the UI.

---

## 2. Broken Access Control (BAC)

### 2.1 Functional pivot (vertical/horizontal)
- Access to endpoints outside the assigned role boundary (user calling /admin/ or /internal/ paths).
- Test: Call admin endpoints with a regular-user token.

### 2.2 Metadata/attribute side-channel
- Restricted object existence leaked via search, typeahead, recent-items, or analytics APIs.
- Test: Search for objects the user should not know exist; check if names/IDs appear in suggestions.

### 2.3 State/session permeability
- External/portal sessions reach internal/standard views or setup menus.
- Test: Change the URL from the portal path to the internal path while using a portal session.

### 2.4 Privilege escalation via parameter tampering
- Role, group, or permission identifiers accepted from client input without server-side re-validation.
- Test: Modify role/permission parameters in requests; check if elevated access is granted.

---

## 3. Insecure Design

### 3.1 Client-assumed authority
- Backend trusts client-supplied security-sensitive values (price, role, status, discount).
- Test: Modify client-side values in requests; check if the backend accepts them without validation.

### 3.2 Workflow decoupling
- Multi-step flows where the final step does not re-verify prerequisite gates were passed.
- Test: Skip directly to the final step of a multi-step process; check if it succeeds.

### 3.3 Semantic ambiguity (over-broad endpoints)
- Single endpoints performing multiple operations (upsert) blurring authorization for create vs update.
- Test: Use an upsert endpoint to create or modify resources the user should not be able to.

### 3.4 Implicit trust in callbacks
- Webhook/callback endpoints accepting state changes without cryptographic signature validation.
- Test: Send a forged callback without a valid signature; check if state changes.

---

## 4. Integrity Failures

### 4.1 Confused deputy / brokerage failures
- Privileged internal services (PDF generators, email notifiers) exploited as proxies for unauthorized access.
- Test: Trigger a privileged service to access resources on behalf of an unauthorized user.

### 4.2 Persistence poisoning via lifecycle actions
- Clone/restore/sync/merge operations creating objects that inherit unauthorized data or permissions.
- Test: Clone a restricted object as an unauthorized user; check if the clone contains restricted data.

### 4.3 Integrity downgrade via versioning
- Legacy API versions bypassing modern security filters while touching production data.
- Test: Call legacy endpoints (v1, SOAP) with requests that would be blocked by current versions.

---

## 5. Injection (Logic and Protocol)

### 5.1 Authorization-bypass injection
- Injected operators (OR 1=1, wildcards) nullifying owner/tenant constraints in queries.
- Test: Inject logical operators into search/filter parameters; check if unauthorized data is returned.

### 5.2 Resolver/graph traversal injection
- Exploiting GraphQL, SOQL, or similar languages to traverse from authorized to unauthorized nodes.
- Test: Craft nested queries or aliases that reach restricted objects through relationship traversal.

### 5.3 SSRF via user-controlled URLs
- Endpoints accepting URLs that the backend fetches, enabling access to internal resources.
- Test: Submit internal URLs (localhost, metadata endpoints) through user-controlled URL parameters.

---

## 6. Security Misconfiguration

### 6.1 Schema/relationship over-exposure
- Introspection, WSDLs, Swagger docs, or tooling APIs revealing internal data model.
- Test: Check if introspection queries, WSDL endpoints, or debug interfaces are accessible.

### 6.2 Verbose error feedback
- Detailed error responses leaking internal keys, owner names, stack traces.
- Test: Trigger errors (invalid IDs, malformed requests) and inspect response bodies.

### 6.3 Default credentials and unnecessary services
- Default accounts, debug endpoints, or unnecessary protocols still active.
- Test: Attempt authentication with known default credentials; probe for debug/admin endpoints.

---

## 7. Logging and Alerting Failures

### 7.1 Operational PII/PHI leakage
- Sensitive data (tokens, IDs, PII) over-logged into broadly accessible logs.
- Test: Review log access controls and content; check if sensitive payloads appear in plaintext.

### 7.2 Anti-forensic capabilities
- Users can alter or delete audit trails of their own actions.
- Test: Attempt to modify or delete audit log entries as the logged user.

---

## 8. Exceptional Conditions

### 8.1 Race condition / concurrency gaps
- Temporary windows during data syncs where ownership is not yet committed.
- Test: Send concurrent requests during state transitions; check for unauthorized access windows.

### 8.2 Fail-open on timeout
- Authorization middleware granting access when the authorization service is unavailable.
- Test: Simulate authorization service unavailability; check if requests are allowed through.

---

## 9. Platform-Specific Patterns

### 9.1 GraphQL: single endpoint, vulnerabilities in operations
- GraphQL uses one endpoint (POST /graphql). Vulnerabilities occur in query/mutation operations and field arguments.
- Operations taking object IDs without ownership checks enable unauthorized access.
- Nested fields with resolvers that don't filter by parent ownership.
- Batch/alias queries enabling enumeration in one request.
- Test: With two different user tokens, call the same operation with the same object ID.

### 9.2 SOQL and Salesforce record-level access
- SOQL queries without WITH SECURITY_ENFORCED or ownership filters.
- Cross-object subqueries that may not respect sharing rules.
- Apex classes running 'without sharing' accepting record IDs from client controllers.
- Lightning/Aura UI API field injection bypassing frontend read-only attributes.
- Test: Run queries as different users; check for WITH SECURITY_ENFORCED; test field injection via intercepted requests.

### 9.3 HAR capture analysis
- Extract actual URLs, record IDs, GraphQL operations, and actions from HAR captures.
- Identify endpoints accepting object IDs without documented authorization checks.
- Look for PII in response bodies, cross-tenant indicators, and write operations without ownership verification.

---

## Generic Verification Steps

1. Identify all endpoints/operations that take an object identifier (path, query, body, field argument).
2. For each, with two different authenticated users/tokens, request the same object ID. If both succeed, authorization is broken.
3. Check documentation for explicit authorization/permission for the object; if missing, treat as suspected vulnerability.
4. For list endpoints, ensure responses are filtered by tenant/user.
5. For linked resources, verify related entities enforce the same or stricter access control as the parent.
6. For write operations, verify the caller owns or is allowed to modify the resource.
7. For batch/bulk endpoints, verify responses only include authorized objects.
8. For callbacks/webhooks, verify signature or origin validation is enforced.
9. For configuration: verify introspection is disabled, errors are generic, and debug endpoints are removed.
10. For logs: verify sensitive data is not logged in plaintext accessible to unauthorized personnel.
