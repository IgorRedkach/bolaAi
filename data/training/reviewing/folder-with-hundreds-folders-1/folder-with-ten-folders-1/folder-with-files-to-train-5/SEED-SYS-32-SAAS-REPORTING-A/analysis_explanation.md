## Analysis reasoning

I reviewed the InsightGraph Analytics API v5.0.0 architecture specification, Java Spring resolver code, and HAR trace.

1. **DoS mechanism localization**: the Java `reportsTo` resolver performs `db.fetchUserById(managerId)` on every call — described as "High-cost synchronous DB fetch/mapping." The Neo4j graph database traversal for each level involves multiple DB roundtrips. At 50 levels, the resolver is called 50 times sequentially. The HAR request time of 30,005ms (30 seconds) confirms the server processed the recursive execution for the full timeout window before the load balancer terminated the connection.

2. **Two-layer failure (depth + complexity)**: section 3.2 states the server enforces neither a maximum query depth nor a complexity limit. Section 4.0 explicitly documents that the recursion limit was removed (RISK-GRPH-804) and replaced only with a client-side UI limit. A client-side limit is not a security control — any HTTP client (including the attacker's tool) can bypass it. The HAR `comment` confirms the 50-level payload was accepted by the server without pre-execution rejection.

3. **HAR 504 as definitive DoS signal**: HTTP 504 Gateway Timeout means the upstream server did not respond within the load balancer's 30-second timeout. The response header `x-load-balancer-timeout: 30000ms` confirms the termination cause. The request time of `30005ms` aligns exactly with the timeout threshold. The server did not respond — it was blocked on the recursive DB calls for the entire 30-second window. In a multi-tenant cluster (section 1.0), this blocks all concurrent requests from all tenants during this period.

4. **Attack cost vs. impact asymmetry**: the attacker sends one HTTP request (one unit of rate limit consumption) and causes 30 seconds of server unavailability. This is a very high attack amplification ratio — a single authenticated user can cause cluster-wide DoS.

5. **Not a data breach**: this is a pure availability attack — no cross-tenant data is exposed. The vulnerability class is resource exhaustion (Pattern 8.4) triggered by GraphQL structural abuse (Pattern 9.1). The remediation focus is on pre-execution query analysis, not authorization.
