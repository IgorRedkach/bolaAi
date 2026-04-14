# Analysis Explanation
**Folder:** GQL-0293-SMART-HOME | **Context source:** This folder's context.txt only.
- System: NeoBuild BAS Platform, Smart Home/Building Automation
- Host: `api.neobuild-bas-platfor.example.com`
- Attacker tenant: `tenant-feb6`, victim tenant: `tenant-b2f6`
- HAR request: `listResources(tenantId: "tenant-b2f6")` — client-supplied tenantId bypasses JWT check
- **Inconsistency in context.txt:** Request uses `listResources` query but response JSON key is `getResource`. HAR is authoritative.
- Response: `ownerId: other-user-feb6b2f6`, `sensitiveField: CONFIDENTIAL-feb6b2f6`
- `x-request-id: req-feb6b2f6` is a server-assigned response header, not a request header
- Redis keyed by `resourceId` only — no tenant dimension (§2.0 cache note)
- Pattern 1.8: Predictable/sequential IDs — resolver does not enforce tenancy; sequential IDs enable enumeration
**Consistency Guard:** All values from this folder's context.txt only.
