# Analysis Explanation
**Example:** GQL-0326-AEROSPACE — WingTech Maintenance Portal
**Pattern:** 7.1 — Operational PII/PHI leakage (Logging Failures)

---

## Why This Is a Vulnerability

Pattern 7.1 (Logging Failures — Operational PII/PHI leakage) captures cases where sensitive operational data is leaked through the operational response path — not necessarily through log files, but through any unintended disclosure channel in the system's operational flow. In this case, the `updateResource` mutation response includes `sensitiveField` and `internalNotes` of the target record, which belong to a different tenant. The resolver's failure to enforce tenancy allows the attacker to trigger this operational data leakage through a mutation. The classification as Pattern 7.1 rather than BOLA or integrity patterns reflects that the primary observed effect is the leakage of sensitive operational data through a mutation response.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for GQL-0326.

- **System Name:** WingTech Maintenance Portal (§1.0)
- **Domain:** Aerospace / MRO
- **Host:** `api.wingtech-maintenance.example.com` (§6.0 HAR)
- **Attacker tenant:** `tenant-4e69` (§6.0 HAR `x-tenant-id`)
- **Victim tenant:** `tenant-1596` (§6.0 HAR; §6.0 response `tenantId`)
- **Victim resource ID:** `R-2326` (§6.0 HAR mutation `id`)
- **Mutation input:** `{status: "approved", ownerId: "attacker-4e691596"}` (§6.0 HAR)
- **Sensitive data leaked:** `sensitiveField: "CONFIDENTIAL-4e691596"`, `internalNotes: "Internal data exposed"` (§6.0 response)
- **ownerId of victim record:** `other-user-4e691596` (§6.0 response)
- **Vulnerable resolver:** `updateResource` (§6.0 HAR)
- **Root cause:** Mutation resolver does not cross-check record `tenantId` against JWT; sensitive fields returned in mutation response (§4.0 RISK-GQL-326, §5.0)
- **Redis cache key gap:** Cache keyed by `resourceId` only (§2.0)

**Context.txt inconsistency documented:** HAR operation is `updateResource`; response JSON key is `getResource`. Inconsistency recorded — HAR operation is authoritative.

## Domain Risk

Aerospace / MRO (Maintenance, Repair, Overhaul) platforms manage aircraft maintenance records, component lifecycle data, and airworthiness certifications. Leakage of `sensitiveField` and `internalNotes` from maintenance records belonging to another MRO operator could expose proprietary maintenance procedures, component defect histories, or certification status — with potential aviation safety and regulatory implications (FAA, EASA Part 145 compliance).

## What the Model Should Learn

- Pattern 7.1 (Operational PII/PHI leakage) is categorized as a logging/disclosure failure: sensitive data is unintentionally disclosed through an operational path (mutation response).
- The leakage happens through the GraphQL mutation response body — not through logs or error messages — demonstrating that Pattern 7.1 applies to any unintended operational disclosure channel.
- A mutation that returns the full object (common in GraphQL) amplifies the risk: it exposes all `sensitiveField` and `internalNotes` of the record being mutated, even if the requester shouldn't have read access.
- Redis cache without tenant dimension is a secondary leakage path — cached sensitive fields from one tenant's records can be served to another tenant's requests.
