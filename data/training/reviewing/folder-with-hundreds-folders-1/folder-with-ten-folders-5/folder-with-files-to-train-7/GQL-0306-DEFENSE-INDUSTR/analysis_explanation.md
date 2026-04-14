# Analysis Explanation
**Folder:** GQL-0306-DEFENSE-INDUSTR | **Context source:** This folder's context.txt only.
- System: Aegis Vault Secure Repository (GraphQL), Defense Industrial Base
- Host: `api.aegis-vault-secure-r.example.com`
- Attacker tenant: `tenant-b706`, victim tenant: `tenant-67e6`
- HAR query: `getResource(id: "R-2306")`, response key: `getResource` — CONSISTENT, no naming conflict
- Response: `ownerId: "other-user-b70667e6"`, `sensitiveField: "CONFIDENTIAL-b70667e6"`, `internalNotes: "Internal data exposed"`
- Redis cache keyed by `resourceId` only (no tenant dimension — secondary vulnerability, defense data cache poisoning risk)
- `x-request-id: req-b70667e6` is a response header (not a request header)
- Pattern 10.1: ID swap in own request (Single-User) — attacker uses their own valid session (single-user, one token) and replaces their `resourceId` with victim's `R-2306`; `getResource` resolver returns victim data without tenancy check; no re-verification of `ownerId` or `tenantId` post-fetch
- §4.0 RISK-GQL-306: `getResource` resolver fetches by `resourceId` only, no `tenantId` cross-check; `bulkResourceLookup` also lacks per-ID ownership filtering
- Critical domain context: defense industrial base — classified record exfiltration has national security implications
**Consistency Guard:** All values from this folder's context.txt only.
