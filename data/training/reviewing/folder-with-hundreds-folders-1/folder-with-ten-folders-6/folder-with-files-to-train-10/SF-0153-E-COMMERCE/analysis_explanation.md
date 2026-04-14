# Analysis Explanation
**Example:** SF-0153-E-COMMERCE — ShopGrid Marketplace API
**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)

---

## Why This Is a Vulnerability

Pattern 9.2 (Platform — SOQL record-level access) targets the Salesforce-specific authorization model. The `CustomRecord` object has OWD=Private, meaning users can only access records they own or that have been explicitly shared with them. When `CustomRecordController` is declared `without sharing`, this OWD=Private policy is disabled — the SOQL executes in system context and returns any record by ID. The SOQL lacks both `AND OwnerId = :UserInfo.getUserId()` and `WITH SECURITY_ENFORCED`, meaning there is no fallback enforcement. The result is complete record-level access bypass for any CustomRecord in the org.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0153.

- **System Name:** ShopGrid Marketplace API (§1.0)
- **Domain:** E-Commerce / Marketplace
- **Host:** `378be387.lightning.force.com` (§6.0 HAR)
- **Session token:** `00D378BE387!AR378be387...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.CustomObjectController.getRecord` (§6.0)
- **Apex class name (§4.0):** `CustomRecordController` (class) with method `getCustomRecordDetails`
- **Object type:** CustomRecord (§3.0); OWD: Private (§7.0)
- **Victim record ID:** `001E387` (§6.0 HAR params)
- **Victim SSN:** `000-50-3432` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `CustomRecordController` declared `without sharing`; no ownership predicate in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex class is `CustomRecordController.getCustomRecordDetails`; §5.0 and §6.0 HAR use `c.CustomObjectController.getRecord`. The Aura descriptor references `CustomObjectController` while the Apex class is `CustomRecordController` — a naming discrepancy within the context.txt. HAR Aura descriptor is authoritative.

## Domain Risk

E-commerce marketplace CustomRecord objects may represent order details, seller contracts, customer profiles, or payment records with embedded PII. Unauthorized access to `SensitiveData__c` (SSN: `000-50-3432`) and `InternalNotes__c` across all marketplace participants exposes customer financial data, seller PII, and confidential marketplace terms. In a B2B e-commerce context, this could also expose proprietary pricing agreements.

## What the Model Should Learn

- Pattern 9.2 in the context of a custom Salesforce object (`CustomRecord`) demonstrates that the vulnerability applies to both standard and custom objects equally.
- The naming inconsistency between Apex class (`CustomRecordController`) and Aura descriptor (`CustomObjectController`) is a design/maintenance issue that also complicates security review.
- `without sharing` on a `CustomRecord` controller is especially dangerous because custom objects often store the most sensitive, domain-specific data.
- Fix requires both `with sharing` on the class and an ownership predicate in SOQL — one without the other is insufficient.
