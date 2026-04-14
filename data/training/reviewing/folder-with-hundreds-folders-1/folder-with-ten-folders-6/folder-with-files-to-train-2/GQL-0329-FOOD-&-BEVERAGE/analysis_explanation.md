# Analysis Explanation
**Example:** GQL-0329-FOOD-&-BEVERAGE — TraceOrigin Supply API
**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)

---

## Why This Is a Vulnerability

Pattern 10.2 (Single-User — Parameter escalation) describes a session scope extension attack: the attacker uses their own valid session and changes one parameter to extend their access beyond the intended boundary. Here, the escalation vector is the `tenantId` filter argument on `listResources` — supplying a different tenant's ID causes the resolver to return that tenant's resources. The attacker escalates from "can see my own tenant's resources" to "can see any tenant's resources by specifying their tenantId". This is own-session-scope extension: no second account is needed.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0329.

- **System Name:** TraceOrigin Supply API (§1.0)
- **Domain:** Food & Beverage / FMCG
- **Host:** `api.traceorigin-supply-a.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-21c7` (§6.0 HAR `x-tenant-id`)
- **Victim tenant:** `tenant-9394` (§6.0 HAR `listResources` tenantId argument; §6.0 response `tenantId`)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-21c79394"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-21c79394` (§6.0 response)
- **Vulnerable resolver:** `listResources` (§6.0 HAR)
- **Root cause:** `listResources` accepts client-supplied `tenantId` without JWT cross-check (§4.0, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**Context.txt inconsistency documented:** HAR operation is `listResources`; response JSON key is `getResource`. Inconsistency recorded — HAR operation is authoritative.

## Domain Risk

Food & Beverage / FMCG supply chain traceability platforms manage ingredient provenance, supplier contracts, batch records, and food safety audit trails. Cross-tenant access to supply chain records could expose proprietary supplier relationships, ingredient sourcing secrets, or food safety audit findings of competing FMCG manufacturers — with competitive intelligence and potential food safety reporting implications.

## What the Model Should Learn

- Pattern 10.2 in GraphQL occurs when a resolver argument allows a user to specify scope that should be server-controlled.
- The `tenantId` parameter on `listResources` is the escalation vector: it converts a scoped list into an unscoped cross-tenant data dump.
- The fix is straightforward: `listResources` should always use `context.jwt.tenantId`, never `args.tenantId`.
- This is distinct from Pattern 3.3 (semantic ambiguity) even though both involve a `tenantId` filter: 10.2 is about a single user extending their session scope, while 3.3 is about the API's architectural design ambiguity.
