# Expected Response

## System
- **Domain:** Automotive / V2X Telematics (Salesforce-Integrated)
- **System:** AetherDrive V2X Telematics (Salesforce-Integrated)
- **Example ID:** SF-0005

## Priority Findings

### Finding 1: Automotive V2X Salesforce — Insecure Design via Client-Assumed Authority in Aura getCaseDetails Exposes Cross-Ownership Vehicle Case Data (Pattern 3.1)
**Severity:** High
**Category:** Insecure Design / Client-Assumed Authority (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-005/RISK-SF-006): The `CaseController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 3.1 — client-assumed authority): the Aura action trusts the client-supplied `caseId` as an authoritative identity claim, rather than validating it against `UserInfo.getUserId()` server-side. An attacker submitted `c.CaseController.getCaseDetails` with `caseId: "001A78A"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-47-9912"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Automotive V2X, exposure of vehicle case records containing PII enables identity theft.

**Evidence from HAR:**
- Request: `POST https://2e0ca78a.lightning.force.com/aura`
- Aura action descriptor: `c.CaseController.getCaseDetails`
- `aura.token`: `undefined`
- Params: `caseId: "001A78A"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "001A78A"`, `Name: "Victim Case Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-47-9912"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-005 | CaseController declared `without sharing` |
| context.txt §4.0 | RISK-SF-006 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 3.1 | Client-assumed authority — caseId trusted without validation |
| HAR request | params.caseId | 001A78A — victim case ID |
| HAR response | SensitiveData__c | SSN: 000-47-9912 (PII) |
| HAR response | OwnerId | 005VICTIM (client-assumed authority confirmed) |

## Steps to Reproduce

### Step 1 — Aura caseId client-assumed authority (HAR)
```bash
curl -s -X POST 'https://2e0ca78a.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.CaseController.getCaseDetails","callingDescriptor":"UNKNOWN","params":{"caseId":"001A78A","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim V2X case record including `SSN: 000-47-9912`. **Secure:** FORBIDDEN — `with sharing`; SOQL restricted to caller ownership.

## Remediation
1. Declare `CaseController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to the SOQL WHERE clause.
3. Never trust client-supplied record IDs as authority; always validate against current user context.
4. Validate `aura.token`; define server-side field allowlist.
