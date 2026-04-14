## System

- System: TaskFlow Project Management API v6.0.0
- Domain: SAAS / PROJECT MANAGEMENT / WORK TRACKING
- Risk ID: RISK-GRPH-903

## Findings

### 1. GraphQL Alias Batching Rate-Limit Bypass + Predictable Sequential IDs — 2,000 Parallel BOLA Probes in One Request (Pattern 9.1 + Pattern 1.8)

The `projects` table uses `SERIAL PRIMARY KEY` (`project_id`) — auto-incrementing integers (section 5.0, RISK-GRPH-903). An attacker who knows one of their own project IDs (e.g., `12450`) can deduce adjacent IDs. The Apollo GraphQL server processes all aliased fields in a single HTTP request. The attacker submits 2,000 aliases (`p10001` to `p12000`) in one POST — the API Gateway's rate limit counts this as one request.

The Python resolver (section 6.1) returns the full project object for membership-authorized projects and `null` for unauthorized ones. The attacker scans the response for non-null entries to identify cross-tenant project data.

**HAR evidence**: single POST `https://api.taskflow.com/graphql`, body 128,400 bytes, `"Payload containing 2,000 aliased fields"`. Response header `x-resolver-count: 2000` confirms 2,000 resolver executions. Response includes non-null entries: `p10003: {"projectName": "Q3 Marketing Budget (Tenant B)", "confidentialNotes": "Need to secure $5M in funding before launch."}` and `p10156: {"projectName": "Engineering Roadmap 2027", "confidentialNotes": "Pivot to Go-lang for performance critical services."}` — cross-tenant confidential project data returned to the attacker.

### 2. Soft Authorization Failure Enables Silent Enumeration (Pattern 9.1 side-channel)

The resolver (section 6.1) returns `None` on both BOLA failure and non-existent ID:

```python
if not is_member:
    # VULNERABILITY 9.1: The soft 'None' return value allows the attacker to efficiently check
    # for the existence of non-owned resources without triggering a hard 403 HTTP error.
    return None
```

The response is indistinguishable between "does not exist" and "exists but unauthorized" — both return `null`. However, note that the resolver performs `check_membership(user_id, id)` — this requires the project to exist first (fetched from the DB). For non-existent IDs, `fetchone()` returns None before the membership check. The response timing difference (DB lookup hit vs. miss) creates a subtle timing side-channel, but the primary enumeration method is the presence of populated objects in the response for IDs where the resolver's BOLA check passes.

## Evidence

- **HAR trace**: request 128KB with 2,000 aliases; `x-resolver-count: 2000`; HTTP 200 OK; populated non-null entries for `p10003` and `p10156` with cross-tenant `confidentialNotes`; response 74.5KB.
- **Python resolver** (section 6.1): `return None` on both non-existent and unauthorized — soft fail; no hard 403 or GraphQL error raised.
- **Schema** (section 5.0): `project_id SERIAL` — auto-increment integer; `confidential_notes TEXT` — sensitive corporate IP.
- **Architecture** (section 3.2, RISK-GRPH-903): sequential IDs intentional for DB indexing; soft null return to avoid verbose errors — both documented as the risk combination.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.taskflow.com
Authorization: Bearer <ATTACKER_USER_JWT>
Content-Type: application/json

{"query": "query MassProjectEnumeration { p10001: project(id: 10001) { projectName confidentialNotes } p10002: project(id: 10002) { projectName confidentialNotes } ... p12000: project(id: 12000) { projectName confidentialNotes } }"}
```

Expected secure outcome: HTTP 400 — alias depth limit exceeded; or all unauthorized IDs return a hard GraphQL error preventing enumeration.  
Observed vulnerable outcome: HTTP 200 OK, `x-resolver-count: 2000`, cross-tenant project names and confidential notes in non-null response fields.

## Remediation

- **Enforce a GraphQL alias/operation complexity limit** (RISK-GRPH-903): reject queries with more than a configurable maximum number of aliases (e.g., 10–20 per request) — restores the effectiveness of HTTP-level rate limiting.
- **Raise a hard GraphQL error on BOLA failure, not `null`**: throw `GraphQLError("Project not found")` for both non-existent and unauthorized IDs — this prevents the distinction between "null (authorized path failed)" and error from being used for enumeration. Do not distinguish between not-found and forbidden (return 404-style error for both).
- **Migrate `project_id` to non-sequential UUIDs**: replace `SERIAL` with `UUID DEFAULT gen_random_uuid()` — remove sequential predictability at the ID level.
- **Never return `confidential_notes` via enumerable queries**: `confidentialNotes` should require explicit membership verification at the field resolver level, separate from the top-level project authorization.
