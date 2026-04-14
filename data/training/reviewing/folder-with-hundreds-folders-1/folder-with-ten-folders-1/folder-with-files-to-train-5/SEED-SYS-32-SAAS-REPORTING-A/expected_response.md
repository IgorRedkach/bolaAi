## System

- System: InsightGraph Analytics API v5.0.0
- Domain: SAAS / DATA ANALYTICS / REPORTING / USER GRAPH
- Risk ID: RISK-GRPH-804

## Findings

### 1. GraphQL Deep Query — Recursive `reportsTo` Exhausts Server CPU/Memory (Pattern 9.1 + Pattern 8.4)

The `User.reportsTo` Java resolver (section 6.1) performs a synchronous DB roundtrip on every invocation with no depth counter or recursion guard:

```java
// VULNERABILITY 9.1 & 8.4: Missing Depth/Complexity Limit
// The code FAILS to use context to check if ... a custom depth counter is exceeded.
String managerId = db.findManagerIdByUserId(subordinate.getId());
if (managerId == null) {
    return null;  // Stops recursion only if no manager exists
}
return db.fetchUserById(managerId);  // High-cost synchronous DB fetch on every recursive call
```

The GraphQL-Yoga server has no complexity analyzer plugin and no maximum query depth enforcement (section 3.2, RISK-GRPH-804). The recursion limit removed during Epic ANALYTICS-501 was never replaced with a server-side guard. An attacker submits a single query nesting `reportsTo` 50 levels deep. The resolver executes 50 synchronous DB roundtrips in sequence, each involving Neo4j graph traversal. This blocks the main application thread, spikes CPU to 100%, and consumes temporary memory for the deeply nested JSON object.

**HAR evidence**: POST `https://api.insightgraph.com/graphql`. Request body: 10,240 bytes, `"Payload contained 50 levels of 'reportsTo' recursion"`. Request time: **30,005ms** — the request held the connection for 30 seconds. Response: **HTTP 504 Gateway Timeout**, `x-load-balancer-timeout: 30000ms`. The upstream load balancer terminated the connection due to the exhausted timeout. The server was unresponsive for the entire 30s window — a complete DoS for all concurrent tenants in the multi-tenant cluster.

## Evidence

- **HAR trace**: request `time: 30005` ms — 30s response time. HTTP 504 Gateway Timeout. Header `x-load-balancer-timeout: 30000ms` confirms load balancer terminated the connection. Body comment: "50 levels of `reportsTo` recursion."
- **Java resolver** (section 6.1): no depth check, no recursion limit; `db.fetchUserById()` executed synchronously for each level — "High-cost synchronous DB fetch/mapping is executed on every recursive call."
- **Architecture** (section 3.2): "the Java resolver for `User.reportsTo` recursively calls itself until the Node.js event loop runs out of available memory or the HTTP timeout is hit."
- **System debt** (section 4.0, RISK-GRPH-804): recursion limit explicitly removed during Epic ANALYTICS-501, replaced with client-side UI limit only. Server-side guard was never added.

## Reproduction

```http
POST /graphql HTTP/2.0
Host: api.insightgraph.com
Authorization: Bearer <ATTACKER_USER_JWT>
Content-Type: application/json

{"query": "query RecursiveDoS { user(id: \"usr-88192A\") { id reportsTo { id reportsTo { id reportsTo { id reportsTo { id reportsTo { id reportsTo { id reportsTo { id reportsTo { id reportsTo { id reportsTo { id reportsTo { displayName } } } } } } } } } } } } }"}
```

(50 levels of `reportsTo` in the full payload — truncated above for brevity.)

Expected secure outcome: HTTP 400 — query depth limit exceeded (max depth 5 or 10); request rejected before execution.  
Observed vulnerable outcome: HTTP 504 Gateway Timeout — server blocked for 30 seconds; all concurrent users experience DoS.

## Remediation

- **Add a GraphQL query depth limit** (RISK-GRPH-804): configure GraphQL-Yoga with `depthLimit(10)` or equivalent — reject queries where field nesting exceeds the maximum before execution begins.
- **Add a query complexity limit**: calculate the estimated computation cost of the query pre-execution using a complexity analysis plugin; reject queries above a configurable threshold.
- **Restore the server-side recursion guard removed in ANALYTICS-501**: add a depth counter to the `reportsTo` resolver: pass a `maxDepth` context argument, decrement on each recursive call, and return `null` when `maxDepth <= 0`.
- **Use asynchronous, non-blocking DB calls**: the synchronous DB pattern (`db.fetchUserById()`) blocks the Java thread — switching to async/reactive DB calls would reduce the impact of deep queries on concurrent requests.
