# Analysis Explanation
**Example:** SF-0120-FINTECH — PayBridge Transaction API
**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)

---

## Why This Is a Vulnerability

Pattern 1.5 (BOLA — Multi-tenant / cross-tenant access) is the canonical multi-tenancy isolation failure. In a fintech payments gateway hosted on Salesforce, Lead objects may represent merchant onboarding leads, payment partner leads, or institutional customer records — all partitioned across tenants by OWD=Private. When `LeadController` runs `without sharing` and the SOQL has no ownership predicate, any tenant's authenticated user can directly address any other tenant's Lead record by its ID. The cross-tenant boundary is entirely absent at the controller level; the only "isolation" that existed was the Salesforce OWD model, which `without sharing` nullifies.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0120.

- **System Name:** PayBridge Transaction API (§1.0)
- **Domain:** Fintech / Payments Gateway
- **Host:** `b1704582.lightning.force.com` (§6.0 HAR)
- **Session token:** `00DB1704582!ARb1704582...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.LeadController.getLeadData` (§6.0)
- **Apex class method (§4.0):** `LeadController.getLeadDetails`
- **Object type:** Lead (§3.0); OWD: Private (§7.0)
- **Victim record ID:** `0014582` (§6.0 HAR params)
- **Victim SSN:** `000-78-1841` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `LeadController` declared `without sharing`; no ownership check in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex method is `getLeadDetails`; §5.0 and §6.0 HAR use `c.LeadController.getLeadData`. HAR Aura descriptor is authoritative.

## Domain Risk

Fintech / payments gateway platforms are subject to PCI-DSS, GDPR, and financial data protection regulations. A multi-tenant payments gateway where any tenant can access another tenant's Lead records (containing SSN: `000-78-1841`, internal notes about payment arrangements, and merchant data) represents a severe regulatory and business risk. Cross-tenant access to merchant onboarding PII or financial lead data could enable competitive intelligence, identity theft, or fraudulent payment account creation.

## What the Model Should Learn

- Pattern 1.5 (BOLA multi-tenant) in Salesforce context: `without sharing` is the mechanism that removes the tenant isolation boundary; the vulnerability is the complete absence of cross-tenant scoping.
- In multi-tenant Salesforce environments, OWD=Private is the primary tenant isolation mechanism. `without sharing` destroys this boundary regardless of the OWD setting.
- Pattern 1.5 differs from 10.2 (parameter escalation) in that 1.5 explicitly involves cross-tenant (multi-tenant) access, not just extending one's own session scope within a single tenant.
- PCI-DSS and fintech regulations impose mandatory controls on cross-tenant data isolation — BOLA 1.5 in a payments context is a direct compliance violation.
