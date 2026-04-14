# Analysis Explanation
**System analysed:** AquaGrid Meter Management — GQL-0239 (Water Utilities / Smart Meters)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-239: `updateResource` lacks `tenantId` ownership check.
2. §5.0 Pattern 9.1: GraphQL single endpoint vulnerability; all mutations including sensitive operational writes are concentrated at one endpoint without per-operation tenancy enforcement.
3. HAR: `tenant-178b` issues `updateResource(id: "R-2239", input: {status: "approved", ownerId: "attacker-178b8c44"})` → `tenant-8c44` meter data: `CONFIDENTIAL-178b8c44`, `req-178b8c44`.
4. Water Utilities domain: smart meter configurations, billing data, network topology — critical infrastructure; cross-tenant write enables meter tampering and false billing injection.

## Consistency Guard
Attacker: `tenant-178b`. Victim: `tenant-8c44`. Resource: `R-2239`. Sensitive: `CONFIDENTIAL-178b8c44`. ownerId: `other-user-178b8c44`. Request: `req-178b8c44`. All from this folder only.
