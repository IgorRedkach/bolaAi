# Analysis Explanation
**System analysed:** ThreatLens SOC Platform — GQL-0083 (Cybersecurity / SOC)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 6.1 (schema/relationship over-exposure — misconfiguration). Introspection enabled in production exposes SOC resolver structure.
2. §4.0 RISK-GQL-083: `getResource` fetches by ID only — no tenantId match.
3. HAR: `getResource(id: "R-2083")` from `tenant-1bca`. Response `tenant-e4c7`: `CONFIDENTIAL-1bcae4c7`. `x-request-id: req-1bcae4c7`.
4. SOC context: introspection exposure on a security platform is especially severe — attackers can map all available queries before attacking.

## Consistency Guard
Tenant IDs: `tenant-1bca`, `tenant-e4c7`. Resource: `R-2083`. ownerId: `other-user-1bcae4c7`. Leaked: `CONFIDENTIAL-1bcae4c7`. Request: `req-1bcae4c7`. All from this folder only.
