# Analysis Explanation
**Example:** SF-0152-FINANCIAL-SERVI — NexaBank Open Finance API
**Pattern:** 3.1 — Client-assumed authority (Insecure Design)

---

## Why This Is a Vulnerability

Pattern 3.1 (Insecure Design — Client-assumed authority) describes a fundamental authorization design error: the server assumes clients will only present record IDs within their authorized scope. In financial services, this is especially dangerous because the system's trust model is inverted — the server should derive authorization from the authenticated session, but instead trusts the client to scope their own requests. The `c.ContactController.updateContact` Aura descriptor name suggests a write operation, yet the underlying `getContactDetails` Apex method performs a read — an additional design inconsistency. Combined with `without sharing`, any authenticated user can read any Contact record.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0152.

- **System Name:** NexaBank Open Finance API (§1.0)
- **Domain:** Financial Services / Retail Banking
- **Host:** `7c2e47c8.lightning.force.com` (§6.0 HAR)
- **Session token:** `00D7C2E47C8!AR7c2e47c8...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.ContactController.updateContact` (§6.0)
- **Apex class method (§4.0):** `ContactController.getContactDetails`
- **Object type:** Contact (§3.0); OWD: Private (§7.0)
- **Victim record ID:** `00147C8` (§6.0 HAR params)
- **Victim SSN:** `000-94-7686` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `ContactController` declared `without sharing`; no ownership check in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex method is `getContactDetails`; §5.0 and §6.0 HAR use `c.ContactController.updateContact`. HAR Aura descriptor is authoritative. The `updateContact` descriptor name for a read operation is an additional design inconsistency noted.

## Domain Risk

Retail banking Contact records contain customer PII (SSN: `000-94-7686`), account relationships, internal credit notes, and know-your-customer (KYC) data. Unauthorized access in a financial services context triggers GDPR, CCPA, PCI-DSS, and banking regulation obligations. Cross-customer PII exposure in a bank could enable identity theft, account takeover, or fraudulent credit applications.

## What the Model Should Learn

- Pattern 3.1 in financial services is a direct regulatory compliance failure — not just a security issue.
- The `updateContact` descriptor name backed by a read-only Apex method demonstrates how misleading descriptor names can obscure security review.
- `without sharing` in financial services Salesforce implementations is a critical risk: it removes the only platform-level protection for customer financial data.
- Server-side trust model: authorization must be derived from the JWT/session, never from client-supplied record IDs.
