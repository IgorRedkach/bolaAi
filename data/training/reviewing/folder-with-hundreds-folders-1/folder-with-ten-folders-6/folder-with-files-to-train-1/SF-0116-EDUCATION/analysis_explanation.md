# Analysis Explanation
**Example:** SF-0116-EDUCATION — LearnPath Assessment Platform
**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)

---

## Why This Is a Vulnerability

Pattern 2.4 (BAC — Privilege escalation via parameter tampering) captures cases where an attacker exploits a parameter that controls record access to escalate their effective privilege. The `accountId` parameter in the Aura action payload is fully client-controlled. Because `AccountController` runs `without sharing`, Salesforce's OWD=Private sharing model is bypassed entirely — the SOQL executes as the system user, not the requesting user. There is no server-side ownership check. An attacker can substitute any `accountId` in the Aura message body to retrieve Account records they are not authorised to access, exposing `SensitiveData__c` (SSN) and `InternalNotes__c`.

## Context Consistency Analysis

All details in this file are derived exclusively from `context.txt` for SF-0116.

- **System Name:** LearnPath Assessment Platform (§1.0)
- **Domain:** Education / EdTech LMS
- **Host:** `c32ea424.lightning.force.com` (§6.0 HAR)
- **Session token:** `00DC32EA424!ARc32ea424...` (§6.0 HAR)
- **HAR Aura descriptor (authoritative):** `c.AccountController.getAccounts` (§6.0)
- **Apex class method (§4.0):** `AccountController.getAccountDetails`
- **Object type:** Account (§3.0)
- **Victim record ID:** `001A424` (§6.0 HAR params)
- **Victim SSN:** `000-86-9244` (§6.0 response `SensitiveData__c`)
- **Victim OwnerId:** `005VICTIM` (§6.0 response)
- **Root cause:** `AccountController` declared `without sharing`; no ownership check in SOQL (§4.0, §7.0, §8.0)

**Context.txt inconsistency documented:** §4.0 Apex method is `getAccountDetails`; §5.0 and §6.0 HAR use `c.AccountController.getAccounts`. HAR Aura descriptor is authoritative for the exploit path.

## Domain Risk

Education / EdTech LMS platforms store student records, PII, academic performance data, and financial aid information in Salesforce Account objects. Unauthorized access to `SensitiveData__c` (SSN: `000-86-9244`) constitutes a FERPA violation and an identity theft risk for affected students or educational institution contacts.

## What the Model Should Learn

- Pattern 2.4 (parameter tampering) in Salesforce Aura occurs when the `params` object of an Aura action carries a record ID that the controller uses without ownership validation.
- `without sharing` is the root enabling condition — it disables OWD enforcement entirely.
- SOQL must include `AND OwnerId = :UserInfo.getUserId()` OR `WITH SECURITY_ENFORCED` to enforce record-level access.
- The Aura `fields` array as a parameter is also a mass-assignment risk (Pattern 1.12) but Pattern 2.4 is the primary finding here.
