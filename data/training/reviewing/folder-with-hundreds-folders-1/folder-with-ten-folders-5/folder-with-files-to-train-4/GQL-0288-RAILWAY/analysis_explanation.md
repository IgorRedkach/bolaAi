# Analysis Explanation
**Folder:** GQL-0288-RAILWAY | **Context source:** This folder's context.txt only.
- System: RailCore Operations API, Railway/SCADA
- Host: `api.railcore-operations-.example.com` (trailing dash present in context.txt)
- Attacker tenant: `tenant-e80c`, victim tenant: `tenant-7f1c`
- HAR request operation: `bulkResourceLookup(ids: ["R-2288", "R-1288", "R-3288"])`
- **Inconsistency in context.txt:** Request uses `bulkResourceLookup` mutation but response JSON key is `getResource`. HAR is authoritative for exploit path.
- Response: `ownerId: other-user-e80c7f1c`, `sensitiveField: CONFIDENTIAL-e80c7f1c`
- `x-request-id: req-e80c7f1c` is a server-assigned response header, not a request header
- Redis keyed by `resourceId` only — no tenant dimension (§2.0 cache note)
- Pattern 1.2: Related/linked resource BOLA — bulk lookup traverses tenant boundaries
**Consistency Guard:** All values from this folder's context.txt only.
