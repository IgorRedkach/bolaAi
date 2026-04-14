# Analysis Explanation
**Example:** GQL-0327-NON-PROFIT — GrantFlow CRM API
**Pattern:** 9.1 — GraphQL: single endpoint vulnerabilities (Platform)

---

## Why This Is a Vulnerability

Pattern 9.1 (Platform — GraphQL single-endpoint vulnerabilities) is specific to GraphQL's single-endpoint architecture (`POST /graphql`). Unlike REST APIs where different HTTP methods and paths naturally segment operations, all GraphQL operations — queries, mutations, subscriptions — share a single URL. This means: (1) traditional path-based access controls and gateway rules are ineffective; (2) there is no natural enforcement boundary between operation types; (3) per-operation authorization must be explicitly implemented at the resolver level. When `getResource` lacks a `tenantId` JWT cross-check, the single-endpoint pattern means the attacker can reach any resolver from the same URL with a valid JWT.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0327.

- **System Name:** GrantFlow CRM API (§1.0)
- **Domain:** Non-Profit / Grant Management
- **Host:** `api.grantflow-crm-api.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-9df8` (§6.0 HAR `x-tenant-id`)
- **Victim tenant:** `tenant-07fd` (§6.0 HAR; §6.0 response `tenantId`)
- **Victim resource ID:** `R-2327` (§6.0 HAR)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-9df807fd"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-9df807fd` (§6.0 response)
- **Vulnerable resolver:** `getResource` (§6.0 HAR; §4.0 RISK-GQL-327)
- **Root cause:** `getResource` fetches by `resourceId` only, no `tenantId` JWT cross-check; single-endpoint pattern has no per-operation enforcement (§4.0, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**No operation name inconsistency:** HAR operation `getResource` matches response key `getResource`. Context is internally consistent.

## Domain Risk

Non-profit grant management platforms handle donor data, grant recipient PII, beneficiary records, and grant fund details. Cross-tenant access to grant records could expose the identities and needs of vulnerable beneficiaries (individuals or communities receiving grant funds), proprietary grant application content, or donor-restricted fund usage data.

## What the Model Should Learn

- Pattern 9.1 highlights the platform-specific risk of GraphQL's single-endpoint design: authentication passes, but authorization must be re-enforced at every resolver because path-based controls are ineffective.
- Per-operation authorization is not optional in GraphQL — the single endpoint means all resolvers are equally reachable from one URL.
- The vulnerability manifests as a standard BOLA-type access (ID-based cross-tenant access), but the platform context (GraphQL single endpoint) is the architectural factor that makes it Pattern 9.1 rather than 1.x.
- The Redis cache without tenant dimension creates a compounding risk: cached results from one tenant's `getResource` calls can serve another tenant's requests for the same `resourceId`.
