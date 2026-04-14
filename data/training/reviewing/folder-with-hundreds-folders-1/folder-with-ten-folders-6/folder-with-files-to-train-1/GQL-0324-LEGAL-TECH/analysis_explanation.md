# Analysis Explanation
**Example:** GQL-0324-LEGAL-TECH — LexVault eDiscovery API
**Pattern:** 5.2 — Resolver/graph traversal injection (Injection)

---

## Why This Is a Vulnerability

Pattern 5.2 (Injection — Resolver/graph traversal injection) targets GraphQL's nested resolution model. In GraphQL, a query can traverse multiple resolver levels: `getResource → data → sensitiveField`, `getResource → items`, `getResource → data → auditLog`. Each resolver in the chain can independently fetch data. If authorization is only checked at the root resolver (`getResource`) but not re-checked at nested resolvers, an attacker can obtain child data by accessing parent data across tenant boundaries. Furthermore, even the root `getResource` resolver is vulnerable here — it does not check `tenantId` against the JWT at all. The combination means the attacker traverses from the entry point (`getResource(id: "R-2324")`) through the full resolver chain, exposing deeply nested sensitive fields belonging to `tenant-4da5`.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0324.

- **System Name:** LexVault eDiscovery API (§1.0)
- **Domain:** Legal Tech / Document Management
- **Host:** `api.lexvault-ediscovery-.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-472f` (§6.0 HAR `x-tenant-id` header)
- **Victim tenant:** `tenant-4da5` (§6.0 HAR `getResource id`; §6.0 response `tenantId`)
- **Victim resource ID:** `R-2324` (§6.0 HAR)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-472f4da5"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-472f4da5` (§6.0 response)
- **Vulnerable resolver:** `getResource` and nested `data` sub-resolver (§6.0 HAR; §4.0 RISK-GQL-324; §5.0)
- **Root cause:** `getResource` fetches by `resourceId` only, no `tenantId` JWT cross-check; resolver chain follows nested fields without re-authorization (§4.0, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**No operation name inconsistency:** HAR operation `getResource` matches response key `getResource`. Context is internally consistent on this point.

## Domain Risk

Legal discovery and document management platforms contain highly privileged data: evidence in active litigation, attorney-client privileged communications, confidential contracts, and regulatory filings. Cross-tenant access to `sensitiveField` and `internalNotes` of legal documents could expose litigation strategy, breach attorney-client privilege, or enable industrial espionage against opposing parties in legal proceedings. This is a data protection failure with serious professional liability implications.

## What the Model Should Learn

- Pattern 5.2 is specifically about the GraphQL resolver chain traversal path — authorization must be enforced at the root AND at each nested resolver, not just entry point.
- Graph traversal injection exploits GraphQL's design strength (composable queries) as a vulnerability: the deeper the graph can be traversed, the more data can be extracted without additional authorization.
- A root resolver that lacks a tenancy check exposes all child resolvers by transitivity.
- eDiscovery and legal document platforms require the highest authorization assurance at every resolver level due to privilege and confidentiality requirements.
- Redis cache without a tenant dimension enables cross-tenant cache poisoning in addition to the resolver-level flaw.
