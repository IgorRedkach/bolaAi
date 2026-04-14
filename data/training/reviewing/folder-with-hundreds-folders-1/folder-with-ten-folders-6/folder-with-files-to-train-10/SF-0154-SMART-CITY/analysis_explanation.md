# Analysis Explanation
**Example:** SF-0154-SMART-CITY — MetroPulse Traffic Orchestration
**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)

---

## Why This Is a Vulnerability

Pattern 10.2 (Single-User — Parameter escalation) describes an authorized user extending their own session's scope beyond its intended boundary by substituting record IDs. The attacker does not need additional privileges or a second account — their own valid token on `b3b864f1.lightning.force.com` is sufficient. Because `AccountController` runs `without sharing` and lacks SOQL ownership validation, any `accountId` the attacker supplies is returned unconditionally.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0154.

- **System Name:** MetroPulse Traffic Orchestration (§1.0)
- **Domain:** Smart City / Traffic Management
- **Host:** `b3b864f1.lightning.force.com` (§6.0 HAR)
- **Session token:** `00DB3B864F1!ARb3b864f1...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.AccountController.getAccounts` (§6.0)
- **Apex class method (§4.0):** `AccountController.getAccountDetails`
- **Object type:** Account (§3.0); OWD: Private (§7.0)
- **Victim record ID:** `00164F1` (§6.0 HAR params)
- **Victim SSN:** `000-10-1983` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `AccountController` declared `without sharing`; no ownership check in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex method is `getAccountDetails`; §5.0 and §6.0 HAR use `c.AccountController.getAccounts`. HAR Aura descriptor is authoritative.

## Domain Risk

Smart city traffic management Account records with embedded SSN data (`000-10-1983`) represent municipal department accounts, contractor accounts, or personnel records used in traffic orchestration systems. Unauthorized access to these records could expose city infrastructure operator PII, internal traffic management notes, or department-level operational data. Parameter escalation in a critical infrastructure platform like traffic management has public safety implications if operational controls are affected.

## What the Model Should Learn

- Pattern 10.2 in smart city infrastructure is elevated-risk because the platform manages public safety systems.
- The pattern is consistent across domains: `without sharing` + no SOQL ownership predicate = parameter escalation risk, regardless of the business domain.
- Smart city platforms using Salesforce for Account management should treat all Account records as sensitive infrastructure data requiring strong record-level access control.
