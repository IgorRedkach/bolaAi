# Security Vulnerability Patterns

## Overview

This guide covers vulnerability patterns that can be identified by investigating documentation, schemas, API specs, HAR captures, log/network traces, etc. BOLA (Broken Object-Level Authorization) is the primary focus but all classes are in scope when evidenced by artifacts. This guide has been extended to account for high-consequence environments, including critical infrastructure (energy, water, transportation), Defense Industrial Base networks, and interconnected Smart City IoT deployments.

---

## 1. Broken Object-Level Authorization (BOLA)

BOLA occurs when an API does not verify that the authenticated user is allowed to access or modify the specific object they are requesting. Attackers change object identifiers in URLs, query parameters, or request bodies to access other users' data.

### 1.1 ID in path without ownership check
- Endpoints like `GET /api/resources/{id}` must verify the caller owns or is allowed to access that ID.
- Test: With a single valid token, call the endpoint with your own known resource ID (confirm 200), then replace the ID with another user's resource ID. If the same 200 response returns data you do not own, BOLA is confirmed. A second user account is not required for this basic probe.

### 1.2 Related or linked resources
- A restricted main resource may link to an unrestricted related table. Users locked out of the parent can still access child/linked data.
- Test: Query the related resource by parent ID with an unauthorized user.

### 1.3 Bulk or list endpoints
- List endpoints may return all objects if the backend does not filter by user or tenant.
- Test: With a single valid token, call the list endpoint and check whether objects belonging to other users/tenants appear in the results.

### 1.4 Third-party or storage APIs
- URLs or keys allowing access to objects (images, files) without checking requester authorization.
- Test: Change the ID or path segment; check if unauthorized objects are returned.

### 1.5 Multi-tenant / cross-tenant access
- API accepts tenantId/orgId in path or query. Backend does not verify the token matches the requested tenant.
- Test: Use token from tenant A to request resources of tenant B.

### 1.6 Write operations without ownership check
- PATCH, PUT, DELETE endpoints may not verify the caller owns the resource.
- Test: With your own valid token, call the write endpoint with another user's resource ID. If the write succeeds, ownership is not enforced. No second user account is required to detect the gap.

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
- Test: Request the same object ID from two different sessions (different tokens). If the second request returns the first session's cached response (observable via response metadata, e.g., same ETag, response time near-zero, or data mismatch), cache-key isolation failure is confirmed.

### 1.12 Mass assignment via object fields
- Write endpoints accept fields that override ownership, role, or status attributes.
- Test: Submit a write request with additional fields (ownerId, role, status) not shown in the UI.

### 1.13 IoT/SCADA node and device ID manipulation
- Attackers target cyber-physical systems by polling states or sending execution commands to arbitrary hardware serial numbers or PLC node IDs.
- Test: Authenticate as a low-level operator and send a command (e.g., reset, unlock) to a target node ID owned by a different facility.

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

### 2.5 Critical Infrastructure interface exposure
- Web-based Human-Machine Interfaces (HMIs) or cloud-based SCADA systems exposed to unauthenticated or unauthorized corporate environments.
- Test: Attempt to access internal HMI dashboards or cloud-based ICS telemetry from an external or guest network position.

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

### 3.5 Unsecured multi-step critical workflows
- Bypassing physical security logic or industrial control steps by directly calling the final execution API without fulfilling safety interlocks.
- Test: Identify a multi-step operation (e.g., validate safety -> execute valve open) and trigger the final execution endpoint directly.

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

### 4.4 Infrastructure-as-Code (IaC) state file exposure
- Centralized state files containing raw database passwords and internal network architectures exposed to unauthorized development pipelines.
- Test: Request state files for a different deployment project or environment (e.g., retrieving `prod` states using a `dev` token).

### 4.5 Firmware update without signature validation
- Cloud platforms pushing unverified firmware payloads to IoT/SCADA devices, enabling botnet creation or supply chain exploits.
- Test: Provide an attacker-controlled URL for a firmware update payload and verify if the device attempts to fetch and execute it without signature checks.

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

### 5.4 Industrial protocol injection
- Encapsulating malicious operational commands (e.g., Modbus, DNP3) within well-formed web API requests to alter physical measurements or controller logic.
- Test: Inject unexpected parameters or malformed measurement values into API endpoints acting as gateways to PLCs.

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

### 6.4 Cloud storage bucket and network exposure
- Public cloud misconfigurations such as unauthenticated storage buckets, overly permissive security groups (e.g., 0.0.0.0/0 on sensitive ports), and exposed databases.
- Test: Enumerate storage bucket permissions and test external connectivity against cloud instances using default access keys.

### 6.5 Shadow AI and ungoverned ML endpoints
- Unmonitored AI pipelines, fine-tuning infrastructure, and inference endpoints deployed outside of standard corporate governance, creating new backdoor attack surfaces.
- Test: Scan for undocumented AI/ML API endpoints and attempt to execute inference or data-extraction queries without proper authorization.

---

## 7. Logging and Alerting Failures

### 7.1 Operational PII/PHI leakage
- Sensitive data (tokens, IDs, PII) over-logged into broadly accessible logs.
- Test: Review log access controls and content; check if sensitive payloads appear in plaintext.

### 7.2 Anti-forensic capabilities
- Users can alter or delete audit trails of their own actions.
- Test: Attempt to modify or delete audit log entries as the logged user.

### 7.3 Insufficient logging of critical actions
- Failing to log highly auditable events like failed logins, impossible travel, high-value financial transactions, or unauthorized access attempts in critical infrastructure.
- Test: Perform multiple failed authentication attempts and verify if the system generates alerts or successfully records the source IP.

### 7.4 Incomplete log context
- Logs that record events but omit essential forensic context such as timestamps, usernames, or source IPs, rendering post-incident analysis impossible.
- Test: Trigger a security event and review the corresponding log entry to ensure all contextual forensic data is present.

---

## 8. Exceptional Conditions

### 8.1 Race condition / concurrency gaps
- Temporary windows during data syncs where ownership is not yet committed.
- Test: Send concurrent requests during state transitions; check for unauthorized access windows.

### 8.2 Fail-open on timeout
- Authorization middleware granting access when the authorization service is unavailable.
- Test: Simulate authorization service unavailability; check if requests are allowed through.

### 8.3 Fail-open on security checks
- Security controls defaulting to 'allow' when encountering abnormal situations, missing parameters, or downstream component failures.
- Test: Intentionally disrupt a required validation service or provide malformed parameters to force an exception, checking if access is granted.

### 8.4 Resource exhaustion (Denial of Service)
- Applications failing to release resources (e.g., memory, file handles, DB locks) after catching exceptions during heavy processing or file uploads.
- Test: Repeatedly trigger an exception in a resource-heavy endpoint and monitor system availability and response times.

### 8.5 State corruption in critical transactions
- Financial or logistics transactions leaving databases in an exploitable or corrupted state when interrupted mid-process by network disruptions or uncaught exceptions.
- Test: Interrupt a multi-step transaction mid-flight and verify if the system successfully rolls back the database state.

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

### 9.4 SCADA and Industrial Control Systems (ICS)
- Vulnerabilities involving legacy OT protocols, web-based HMIs exposed to untrusted environments, and improper input validation (CWE-20) leading to equipment crashes or unauthorized physical control.
- Test: Evaluate web interfaces connected to PLCs for standard web vulnerabilities (XSS, Buffer Overflows) and ensure strict authentication gates separate IT and OT environments.

---

## 10. Single-User Authorization Expansion

These patterns involve a **single authenticated user** who extends their own expected permissions without needing a second account. The attacker is the victim of their own expanded access — they use their valid session to reach objects, operations, or states they were never granted.

### 10.1 ID swap in own request
- Attacker holds a valid session and substitutes another user's resource ID in their own authenticated request.
- Test: Use your own token; replace your resource ID with an incremented, guessed, or known victim ID. If data returns, BOLA is confirmed with one token.

### 10.2 Parameter escalation (own session scope extension)
- A user adds or modifies request parameters (status, role, tenantId, ownerId) that the backend applies without re-verifying authorization.
- Test: Add or change a scope-expanding parameter (e.g., `?tenantId=other`) in your own authenticated request. If the server returns other-scope data, no second account is needed.

### 10.3 Temporary-ID hijacking
- Short-lived or predictable IDs (job IDs, export tokens, activation links) are guessable within a valid session window.
- Test: Note a short-lived ID from your own flow; increment or pattern-guess adjacent IDs and call the endpoint with your own token.

### 10.4 Lifecycle state bypass
- Multi-step operations (draft → review → approved) expose intermediate states or final-step endpoints callable directly without passing earlier gates.
- Test: With your own valid token, skip directly to the final execution endpoint of a multi-step workflow.

### 10.5 Draft / non-published resource access
- Resources in draft, pending, or soft-deleted states remain accessible by ID even to users who were never granted access to that lifecycle phase.
- Test: Obtain or guess a draft/pending resource ID; call the read endpoint with your own live token.

### 10.6 Subscription / webhook hijacking
- Event subscription endpoints accept arbitrary callback URLs without verifying the subscriber owns the target resource.
- Test: Subscribe to events on another user's resource ID using your own token and your own callback URL.

### 9.5 Smart Cities and IoT Networks
- Manipulation of interconnected cyber-physical systems such as transportation grids, water management, and smart meters via intercepted or spoofed network communications.
- Test: Perform Man-in-the-Middle (MitM) or replay attacks on IoT sensor endpoints to verify cryptographic signatures and request origin validation.
