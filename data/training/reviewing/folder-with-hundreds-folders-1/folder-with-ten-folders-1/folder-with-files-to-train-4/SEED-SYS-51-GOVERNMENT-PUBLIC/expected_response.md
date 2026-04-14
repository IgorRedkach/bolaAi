## System

- System: FirstResponse CAD Integration API v4.0.1
- Domain: GOVERNMENT / PUBLIC SAFETY / EMERGENCY DISPATCH (CJIS)
- Risk: BUG-LOG-004

## Findings

### 1. Fail-Open on AuthZ Timeout — Unauthenticated Emergency Incident Injection (Pattern 8.2)

The Node.js API Gateway middleware (`authCheck.js`, section 6.1) calls the remote AuthZ service with a 500ms hard timeout. On timeout or 5xx error, the `catch` block logs a warning and calls `next()` with `req.userContext = { authenticated: false, userId: null }` — the unauthenticated request is forwarded to the Dispatch Service:

```javascript
} catch (error) {
    console.warn(`AuthZ Service Failed to Respond (Error: ${error.code}). Failing Open.`);
    // The unauthenticated/null userContext is carried forward, allowing the request.
}
// ...
if (!req.userContext.authenticated) {
    // BUG: Developer decided not to block unauthenticated access here
    // The unauthenticated request proceeds with req.userContext.userId = null.
}
next();
```

The AuthZ service is documented (section 4.0) as experiencing transient latency spikes of up to 700ms during its current cloud region migration — exceeding the 500ms threshold. An attacker who amplifies this latency (e.g., flooding `/healthcheck`) can reliably trigger the fail-open window.

**HAR evidence**: POST `https://api.firstresponse-cad.gov/api/v4/incidents/create` — **no `Authorization` header present**. Request time: 610ms (exceeds the 500ms threshold). Response header: `x-authz-result: TIMEOUT_FAIL_OPEN`. Response: HTTP 201 Created, `{"status": "DISPATCH_QUEUED", "incident_id": "inc-88192a-44f2-8921", "source_id": "UNKNOWN", "dispatched_units": 5}`. Five emergency units dispatched to a false "Active Shooter" incident.

### 2. Missing Audit Trail — CJIS Forensic Integrity Failure (Pattern 7.3)

The Go Dispatch Service (section 6.2) extracts `userId` from the request context (set to `""` / `null` by the fail-open middleware) and inserts it into the `emergency_incidents` table. The schema (section 5.0) declares `source_user_id VARCHAR(100)` without a `NOT NULL` constraint, allowing the NULL insert to succeed. The audit logging gate:

```go
if userId != "" && incidentId != "" {
    auditLogger.LogCriticalAction(incidentId, userId, "INCIDENT_CREATED_SUCCESS")
} else {
    // FLAW: If userId is NULL/empty, the incident is created but NO log is generated.
    log.Error("CRITICAL: Incident created without traceable user ID. Audit log skipped.")
}
```

The Audit Log Service only receives an entry when `source_user_id` is non-empty. With `userId = ""`, the audit log call is skipped entirely. The incident exists in the CAD database with `source_user_id = NULL`, with no forensic record of origin, actor, or intent. This is a CJIS compliance violation (section 3.2 mandates `source_user_id` for forensic accountability).

**HAR evidence confirms**: response body contains `"source_id": "UNKNOWN"` — confirming the application recognised the missing identity and still completed the dispatch.

## Evidence

- **HAR trace**: no `Authorization` header; `time: 610` ms > 500ms threshold; `x-authz-result: TIMEOUT_FAIL_OPEN`; HTTP 201 Created; `source_id: UNKNOWN`; 5 units dispatched.
- **Node.js middleware** (section 6.1): `catch` block calls `next()` with null user context; explicit comment confirms fail-open policy; unauthenticated path not blocked.
- **Go Dispatch controller** (section 6.2): inserts `userId` (empty string) without pre-check; skips `auditLogger.LogCriticalAction()` when `userId` is empty — incident created without audit record.
- **Schema** (section 5.0): `source_user_id VARCHAR(100)` — missing `NOT NULL` constraint noted as the flaw enabling NULL insert.
- **Architecture note** (section 4.0, BUG-LOG-004): documents the known NULL `source_user_id` → audit skip bug and the ongoing AuthZ service migration causing latency spikes.

## Reproduction

```http
POST /api/v4/incidents/create HTTP/2.0
Host: api.firstresponse-cad.gov
Content-Type: application/json
x-api-source: external-client

{
  "priority": "CRITICAL",
  "location_json": {"address": "123 Main St, Anytown, USA"},
  "description": "Active shooter reported. Five victims down. High-risk operation."
}
```

Trigger conditions: send during AuthZ service latency spike (>500ms response time), or deliberately stress AuthZ `/healthcheck` endpoint with concurrent requests to amplify the window. No valid `Authorization` header required.

Expected secure outcome: HTTP 401 or HTTP 503 — fail-closed; request rejected when AuthZ is unavailable.  
Observed vulnerable outcome: HTTP 201 Created, `"status": "DISPATCH_QUEUED"`, five units dispatched; no audit log entry created for the incident.

## Remediation

- **Fail-closed on AuthZ timeout**: in `authCheck.js`, replace the empty `if (!req.userContext.authenticated) {}` block with `return res.status(503).json({ error: "Authorization service unavailable. Request rejected." });` — never forward a request without a confirmed authenticated identity.
- **Add `NOT NULL` constraint to `source_user_id`**: `ALTER TABLE emergency_incidents ALTER COLUMN source_user_id SET NOT NULL;` — this prevents NULL inserts at the database level as a defence-in-depth measure.
- **Block dispatch on missing user context in Go service**: before `db.InsertIncident()`, check `if userId == "" { return http.StatusUnauthorized }` — do not rely on the audit log conditional as the only guard.
- **Treat audit log failure as dispatch failure**: if `auditLogger.LogCriticalAction()` fails or is skipped, roll back the incident creation — a CJIS-governed incident without a forensic record must not be committed.
- **Separate the AuthZ migration from the production timeout**: restore full AuthZ service capacity before reducing the fail-open timeout; during migration, route to a warm standby to avoid the latency spike window.
