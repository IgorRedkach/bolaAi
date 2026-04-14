# Analysis Explanation
**System analysed:** OreTrack Fleet Management — SF-0025 (Mining / Resource Extraction, Salesforce)
**Context source:** This folder's context.txt only. No other example was consulted.

## Method
1. §4.0 Apex: `TaskController` declared `without sharing` — OWD=Private for Task bypassed.
2. SOQL: no `AND OwnerId = :UserInfo.getUserId()`.
3. §5.0 Pattern 2.4: BAC — privilege escalation via parameter tampering; attacker tampers `taskId` to victim's record ID, gaining escalated access.
4. HAR: `c.TaskController.getTask`, `taskId: "001F165"` → `OwnerId: "005VICTIM"`, `SSN: 000-84-7708`.
5. Mining/Fleet domain: equipment tracking, operational schedules, fleet telemetry — industrial espionage risk.

## Consistency Guard
Instance: `de71f165.lightning.force.com`. Session: `00DDE71F165!ARde71f165...`. Record: `001F165`. OwnerId: `005VICTIM`. SSN: `000-84-7708`. Descriptor: `c.TaskController.getTask`. All from this folder only.
