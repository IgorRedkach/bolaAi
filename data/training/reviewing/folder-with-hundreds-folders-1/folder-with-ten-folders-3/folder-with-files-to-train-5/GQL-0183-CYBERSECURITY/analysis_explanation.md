# Analysis Explanation
**System analysed:** ThreatLens SOC Platform — GQL-0183 (Cybersecurity / Security Operations)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 RISK-GQL-183: `getResource`/`bulkResourceLookup` resolver fetches by `resourceId` only, no `tenantId` check.
2. §5.0 Pattern 1.8: BOLA — predictable/sequential IDs enable enumeration of cross-tenant records.
3. HAR: `tenant-fca8` queries `bulkResourceLookup(ids: ["R-2183", "R-1183", "R-3183"])` → `tenant-4c39` threat record: `CONFIDENTIAL-fca84c39`, `req-fca84c39`.
4. SOC Platform domain: threat indicators, incident data, detection rules — critical intelligence breach.

## Consistency Guard
Attacker: `tenant-fca8`. Victim: `tenant-4c39`. Resource: `R-2183`. Sensitive: `CONFIDENTIAL-fca84c39`. ownerId: `other-user-fca84c39`. Request: `req-fca84c39`. All from this folder only.
