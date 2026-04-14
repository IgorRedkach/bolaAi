# Analysis Explanation
**System analysed:** TrialVault ClinicalOps API — GQL-0121 (Pharmaceutical)
**Context source:** This folder's context.txt only.

## Method
1. §5.0: Pattern 2.2 (metadata/attribute side-channel). `internalNotes`/`auditLog` exposed via `listResources(tenantId:)`.
2. HAR: `listResources(tenantId: "tenant-c243")` from `tenant-0f80`. Response `tenant-c243`: `CONFIDENTIAL-0f80c243`, `internalNotes: "Internal data exposed"`. `x-request-id: req-0f80c243`.
3. GCP/FDA context: trial metadata has regulatory significance; `internalNotes` may contain adverse event data.

## Consistency Guard
Tenant IDs: `tenant-0f80`, `tenant-c243`. ownerId: `other-user-0f80c243`. Leaked: `CONFIDENTIAL-0f80c243`. Request: `req-0f80c243`. All from this folder only.
