# Analysis Explanation
**Folder:** GQL-0304-SMART-CITY | **Context source:** This folder's context.txt only.
- System: MetroPulse Traffic Orchestration (GraphQL), Smart City/Traffic Management
- Host: `api.metropulse-traffic-o.example.com`
- Attacker tenant: `tenant-d4c1`, victim tenant: `tenant-387e`
- HAR query: `listIntersections(tenantId: "tenant-387e")`, response key: `getIntersection` — **INCONSISTENCY**: HAR uses `listIntersections` but response key is `getIntersection`. HAR operation is authoritative.
- Response: `ownerId: "other-user-d4c1387e"`, `sensitiveField: "CONFIDENTIAL-d4c1387e"`, `internalNotes: "Internal data exposed"` — cross-tenant smart city control data exposed
- Redis cache keyed by `nodeId` only (no tenant dimension — secondary vulnerability)
- `x-request-id: req-d4c1387e` is a response header (not a request header)
- Pattern 7.1: Operational PII/PHI leakage (Logging Failures) — `listIntersections` accepts client-supplied `tenantId`; resolver does not validate against JWT tenantId; sensitive operational fields returned without authorization, constituting operational PII leakage
- §4.0 RISK-GQL-304: `getIntersection` resolver fetches by `nodeId` only without `tenantId` cross-check
- Critical domain context: traffic management infrastructure — leaking operational data of a rival tenant's intersection nodes has public safety implications
**Consistency Guard:** All values from this folder's context.txt only.
