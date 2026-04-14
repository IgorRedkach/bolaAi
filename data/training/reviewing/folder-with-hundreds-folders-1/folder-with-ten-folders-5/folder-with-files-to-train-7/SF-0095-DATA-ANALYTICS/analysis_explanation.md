# Analysis Explanation
**Folder:** SF-0095-DATA-ANALYTICS | **Context source:** This folder's context.txt only.
- System: InsightGraph Analytics API (SF), Data Analytics/BI Platform, OWD: Private on Case
- Host: `a12ddab3.lightning.force.com`, token: `00DA12DDAB3!ARa12ddab3...`
- Descriptor (HAR): `c.CaseController.getCaseDetails`, `caseId: "001DAB3"`
- **No inconsistency:** Apex method `getCaseDetails` in §4.0 matches Aura descriptor `c.CaseController.getCaseDetails` in §6.0 — consistent.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-51-3974`
- Pattern 2.4: Privilege escalation via parameter tampering — attacker with valid session substitutes `caseId` to access records at a privilege level they do not hold; `without sharing` controller bypasses OWD=Private; no ownership predicate in SOQL
- §8.0 RISK-SF-095/096: controller without `with sharing`; no ownership check; client-supplied `caseId` directly interpolated into SOQL
**Consistency Guard:** All values from this folder's context.txt only.
