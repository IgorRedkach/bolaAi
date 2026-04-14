# Analysis Explanation
**Folder:** GQL-0294-CLOUD-IAM | **Context source:** This folder's context.txt only.
- System: VaultGuard IAM API, Cloud IAM/Identity Provider
- Host: `api.vaultguard-iam-api.example.com`
- Attacker tenant: `tenant-e7ff`, victim tenant: `tenant-8829`
- HAR request: `updateResource(id: "R-2294", input: {status: "approved", ownerId: "attacker-e7ff8829"})` — write mutation
- **Inconsistency in context.txt:** §5.0 Pattern 1.9 refers to bulk lookup, but HAR shows `updateResource` write operation with `ownerId` mass assignment. Response key is `getResource` (inconsistent with `updateResource`). HAR is authoritative for exploit demonstration.
- Response: `ownerId: other-user-e7ff8829`, `sensitiveField: CONFIDENTIAL-e7ff8829`
- `x-request-id: req-e7ff8829` is a server-assigned response header, not a request header
- Redis keyed by `resourceId` only — no tenant dimension (§2.0 cache note)
- Pattern 1.9: Batch/bulk lookup BOLA; HAR demonstrates write-side variant with ownerId mass assignment
**Consistency Guard:** All values from this folder's context.txt only.
