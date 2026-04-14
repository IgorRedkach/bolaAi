# Analysis Explanation
**Folder:** GQL-0297-DOCUMENT-SIGNIN | **Context source:** This folder's context.txt only.
- System: SignFlow eSign Platform, Document Signing/eSign
- Host: `api.signflow-esign-platf.example.com`
- Attacker tenant: `tenant-8613`, victim tenant: `tenant-b3a7`
- HAR request: `updateResource(id: "R-2297", input: {status: "approved", ownerId: "attacker-8613b3a7"})` — write mutation
- **Inconsistency in context.txt:** §5.0 describes metadata/attribute side-channel (read-side), but HAR shows write mutation `updateResource`. Response key `getResource` is inconsistent with mutation `updateResource`. HAR is authoritative.
- Response: `ownerId: other-user-8613b3a7`, `sensitiveField: CONFIDENTIAL-8613b3a7`
- `x-request-id: req-8613b3a7` is a server-assigned response header, not a request header
- Redis keyed by `resourceId` only — no tenant dimension (§2.0 cache note)
- Pattern 2.2: Metadata/attribute side-channel — write mutation reveals cross-tenant record attributes and allows unauthorized ownership assignment
**Consistency Guard:** All values from this folder's context.txt only.
