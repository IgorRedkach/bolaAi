# Security Analysis Report
**System:** ChainVault DeFi API (Blockchain / DeFi) — Salesforce-Integrated
**Classification:** SENSITIVE
**Analyst:** Security Analyst Co-Pilot
**Source:** SF-0035 context.txt (sole artifact)

---

## Priority Findings

| # | Severity | Category | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | Single-User / Pattern 10.2 | Parameter escalation — `EventController.updateEvent` with substituted `eventId` exposes cross-user DeFi event records |

---

## Finding 1 — Parameter Escalation: Cross-User DeFi Event Data (CRITICAL)

### Summary
The `EventController` Apex class on ChainVault DeFi API (`48ff8767.lightning.force.com`) is declared `without sharing`. Per §5.0 Pattern 10.2, the `updateEvent` action is vulnerable to session scope extension: attacker substitutes `eventId: "0018767"` to access another user's DeFi transaction event record, including financial identity data and SSN.

**Pattern:** 10.2 — Parameter escalation (own session scope extension) (Single-User)
**Affected controller:** `c.EventController.updateEvent`
**Affected endpoint:** `POST https://48ff8767.lightning.force.com/aura`

### Evidence from HAR
**Request:** `eventId: 0018767` | **Response:** `OwnerId: 005VICTIM`, `SensitiveData__c: SSN: 000-44-9712`

### Evidence Map
| Artifact | Field | Value | Significance |
|---|---|---|---|
| §4.0 Apex | `without sharing` | Class | OWD bypassed |
| §5.0 Pattern 10.2 | Session scope extension | Classification | |
| HAR descriptor | `c.EventController.updateEvent` | Entry point | |
| HAR params | `eventId` | `0018767` | Victim DeFi event |
| HAR response | `SensitiveData__c` | `SSN: 000-44-9712` | Financial identity PII |

### Steps to Reproduce
```bash
curl -s -X POST "https://48ff8767.lightning.force.com/aura" \
  -H "Authorization: Bearer 00D48FF8767!AR48ff8767..." \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'message={"actions":[{"id":"1;a","descriptor":"c.EventController.updateEvent","callingDescriptor":"UNKNOWN","params":{"eventId":"0018767","fields":["Id","Name","OwnerId","InternalNotes__c","SensitiveData__c"]}}]}' \
  --data-urlencode 'aura.token=undefined'
```

### Remediation
1. `public with sharing class EventController {`
2. `WHERE Id = :eventId AND OwnerId = :UserInfo.getUserId()` + `WITH SECURITY_ENFORCED`
3. Server-side field allowlist; validate `aura.token`.
4. DeFi event records contain transaction hashes and financial identity — financial surveillance risk.
