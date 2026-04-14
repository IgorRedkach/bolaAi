# Analysis Explanation
**Example:** GQL-0328-CONSTRUCTION — BuildCore BIM Collaboration
**Pattern:** 10.1 — ID swap in own request (Single-User)

---

## Why This Is a Vulnerability

Pattern 10.1 (Single-User — ID swap) is the simplest BOLA exploit: the attacker uses their own valid session and changes only the resource identifier. No credential theft, no session replay — just changing `R-2328` in the request body. The `getResource` resolver trusts the `resourceId` parameter without verifying the resulting record's `tenantId` against the JWT, so the swap succeeds immediately.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0328.

- **System Name:** BuildCore BIM Collaboration (§1.0)
- **Domain:** Construction / BIM Platform
- **Host:** `api.buildcore-bim-collab.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-4668` (§6.0 HAR `x-tenant-id`)
- **Victim tenant:** `tenant-a49d` (§6.0 HAR; §6.0 response `tenantId`)
- **Victim resource ID:** `R-2328` (§6.0 HAR)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-4668a49d"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-4668a49d` (§6.0 response)
- **Vulnerable resolver:** `getResource` (§6.0 HAR; §4.0 RISK-GQL-328)
- **Root cause:** `getResource` fetches by `resourceId` only, no `tenantId` JWT cross-check (§4.0, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**No operation name inconsistency:** HAR operation `getResource` matches response key `getResource`. Context is internally consistent.

## Domain Risk

Construction / BIM (Building Information Modelling) platforms hold 3D building models, structural engineering specifications, cost estimates, and contractor PII. Cross-tenant access to `sensitiveField` and `internalNotes` of BIM project records could expose proprietary architectural designs, structural specifications, or bidding data of competing construction firms — with significant commercial intelligence value.

## What the Model Should Learn

- Pattern 10.1 (ID swap) is the most basic BOLA attack form: the attacker only changes the ID. If the resolver doesn't verify tenancy, any authenticated user can access any record.
- BIM platforms in construction typically serve multiple competing firms on the same multi-tenant platform — ID swap gives one firm direct access to another's project records.
- The fix is a single server-side check after fetch: `if (record.tenantId !== jwt.tenantId) return Forbidden`.
