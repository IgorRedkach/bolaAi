## System

- System: ClientData GraphQL Interface API v5.0.0
- Domain: ENTERPRISE SAAS / IDENTITY & PROFILE MANAGEMENT
- Risk ID: RISK-GRPH-906

## Findings

### 1. Missing Role-Based Guard on `internalAuditData` Field Resolver — Vertical Privilege Escalation (Pattern 9.1 + Pattern 2.1)

The Java `internalAuditData` field resolver (`ClientResolver.java`, section 6.1) reads the authenticated role from context but performs no check:

```java
String authenticatedRole = env.getContext().get("role");
// VULNERABILITY 2.1 & 9.1: Missing Role Check
// The code FAILS to check: if (!"ADMIN".equals(authenticatedRole)) { return null; }
return db.fetchAuditDataByUserId(client.getUserId());
```

The `internalAuditData` field is defined on the `Client` interface — it is accessible to all concrete types including `BasicUser`. The `@requiresAuth(role: ADMIN)` directive was not applied during the schema merge (RISK-GRPH-906). The resolver retrieves the audit data from the database unconditionally, regardless of the caller's role. A `USER`-role caller using the `me { internalAuditData }` query passes the authentication check, but there is no role gate on the field resolver itself.

**HAR evidence**: POST `https://api.clientdata.com/graphql` with `USER_JWT_88192A`. Query: `me { id displayName internalAuditData }`. Response: HTTP 200 OK. `internalAuditData` returned: `{"lastLoginIP": "203.0.113.45", "failedLoginAttemptsLast24h": 5, "piiChangeHistory": [{"field": "address", "previousValueHash": "SHA256:abcd..."}]}`. Internal security audit data — login IP, failed login count, PII change history — returned to a standard `USER` role.

## Evidence

- **HAR trace**: `USER_JWT_88192A` (low privilege) → `internalAuditData` in query → HTTP 200 OK → internal audit data including login IP, failed attempts, and PII change history in response.
- **Java resolver** (section 6.1): role check variable is set but unused; missing guard annotated explicitly; `db.fetchAuditDataByUserId()` called unconditionally.
- **Architecture** (section 3.2, RISK-GRPH-906): "`@requiresAuth(role: ADMIN)` directive was forgotten during the final schema merge."
- **Schema** (section 5.0): `internal_audit_data JSONB` — comment states "SENSITIVE: Internal login/PII change history" but no DB-level restriction.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.clientdata.com
Authorization: Bearer <USER_ROLE_JWT>
Content-Type: application/json

{"query": "query DataLeakOnInterface { me { id displayName internalAuditData } }"}
```

Expected secure outcome: HTTP 200 with `"internalAuditData": null` or a GraphQL error — `USER` role is not authorized to access this field.  
Observed vulnerable outcome: HTTP 200 OK — `internalAuditData` populated with internal audit data: login IP, failed attempts, PII change history.

## Remediation

- **Add the missing role check to the resolver** (RISK-GRPH-906): implement the commented-out guard: `if (!"ADMIN".equals(authenticatedRole)) { return null; }` — or throw a `GraphQLException` for unauthorized callers.
- **Apply the `@requiresAuth(role: ADMIN)` directive to the field definition**: add the directive to the `internalAuditData` field in the schema so the authorization check is declarative and cannot be overlooked during future refactors.
- **Write a test for low-privilege field access**: add an integration test that queries `internalAuditData` with a `USER` role JWT and asserts the field returns `null` or a forbidden error — this would have caught the missing directive.
- **Audit all fields on the `Client` interface for role-based guards**: any field on a shared interface is accessible to all concrete type resolvers — all sensitive fields must have explicit role checks, not rely on the directive alone.
