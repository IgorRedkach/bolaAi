# Analysis Explanation
**Example:** GQL-0321-PHARMACEUTICAL — TrialVault ClinicalOps API
**Pattern:** 3.3 — Semantic ambiguity (over-broad endpoints) (Insecure Design)

---

## Why This Is a Vulnerability

Pattern 3.3 (Insecure Design — Semantic ambiguity) captures API design flaws where endpoint or resolver semantics are so broad that authorization boundaries become implicit and unenforceable. The `listResources` resolver accepts an explicit `tenantId` filter argument. By design, this filter is meant to aid an authorized user in scoping their own data. However, the resolver never validates whether the supplied `tenantId` matches the JWT's `tenantId`. The semantic ambiguity is that the parameter looks like an ordinary filter, yet functionally it becomes an authorization bypass — anyone can substitute any `tenantId` to retrieve another tenant's clinical trial records.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0321.

- **System Name:** TrialVault ClinicalOps API (§1.0)
- **Domain:** Pharmaceutical / Clinical Trials
- **Host:** `api.trialvault-clinicalo.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-4e51` (§6.0 HAR `x-tenant-id` header)
- **Victim tenant:** `tenant-caf9` (§6.0 HAR `listResources` tenantId argument)
- **Sensitive data exposed:** `sensitiveField: "CONFIDENTIAL-4e51caf9"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-4e51caf9` (§6.0 response)
- **Vulnerable resolver:** `listResources` (§6.0 HAR)
- **Root cause:** `listResources` resolver trusts client-supplied `tenantId` without JWT cross-check (§4.0 RISK-GQL-321, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**Context.txt inconsistency documented:** HAR operation is `listResources`; response JSON key is `getResource`. This is an internal inconsistency in the context.txt. The HAR operation is authoritative for the exploit path. The response key difference is noted without resolving it, faithfully representing what the context.txt states.

## Domain Risk

Pharmaceutical / clinical trial data is subject to strict regulatory controls (FDA 21 CFR Part 11, GCP, HIPAA for PHI components). Unauthorized cross-tenant disclosure of `sensitiveField` and `internalNotes` in clinical trial records could expose PII of trial participants, proprietary compound data, or trial outcomes — with potential for regulatory violations and competitive harm.

## What the Model Should Learn

- Over-broad resolver arguments (client-supplied `tenantId` filter) can function as authorization bypasses even when they appear to be ordinary filters.
- Pattern 3.3 (semantic ambiguity) is distinct from BOLA 1.x: the design flaw is that the API's intended semantics are ambiguous about authority (who controls the `tenantId`), not just that an authorization check is missing.
- The `tenantId` must always be derived from the JWT, never from the request body.
- Redis cache without a tenant dimension enables cross-tenant cache poisoning in addition to the resolver-level flaw.
