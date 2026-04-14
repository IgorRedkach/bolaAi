# Analysis Explanation
**System analysed:** ThreatLens SOC Platform — GQL-0233 (Cybersecurity / SIEM)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-233: `getResource` resolver fetches by `resourceId` only — no `tenantId` ownership check.
2. §5.0 Pattern 3.3: Insecure Design — semantic ambiguity/over-broad endpoint; a single generic resolver handles all `Resource` types with no type-specific access control.
3. HAR: `tenant-1450` queries `getResource(id: "R-2233")` → `tenant-92c1` SIEM data: `CONFIDENTIAL-145092c1`, `req-145092c1`.
4. Cybersecurity/SIEM domain: threat feeds, IOC lists, incident records, detection rules — cross-tenant access constitutes intelligence leakage between competing SOC teams.

## Consistency Guard
Attacker: `tenant-1450`. Victim: `tenant-92c1`. Resource: `R-2233`. Sensitive: `CONFIDENTIAL-145092c1`. ownerId: `other-user-145092c1`. Request: `req-145092c1`. All from this folder only.
