# Analysis Explanation
**Folder:** GQL-0295-DATA-ANALYTICS | **Context source:** This folder's context.txt only.
- System: InsightGraph Analytics API, Data Analytics/BI Platform
- Host: `api.insightgraph-analyti.example.com`
- Attacker tenant: `tenant-cfdd`, victim tenant: `tenant-aa0b`
- HAR request: `listResources(tenantId: "tenant-aa0b")` — client-supplied tenantId bypasses JWT check
- **Inconsistency in context.txt:** Request uses `listResources` but response JSON key is `getResource`. HAR is authoritative.
- Response: `ownerId: other-user-cfddaa0b`, `sensitiveField: CONFIDENTIAL-cfddaa0b`
- `x-request-id: req-cfddaa0b` is a server-assigned response header, not a request header
- Redis keyed by `resourceId` only — no tenant dimension (§2.0 cache note)
- Pattern 1.10: Cross-service identity propagation drift — tenantId not re-validated at resolver level; client-supplied tenantId accepted
**Consistency Guard:** All values from this folder's context.txt only.
