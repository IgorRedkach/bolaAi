# Analysis Explanation
**Folder:** SF-0098-TAX-COMPLIANCE | **Context source:** This folder's context.txt only.
- System: TaxGrid Compliance API (SF), Tax Compliance/RegTech, OWD: Private on CustomRecord
- Host: `2b1362de.lightning.force.com`, token: `00D2B1362DE!AR2b1362de...`
- Descriptor (HAR): `c.CustomObjectController.getRecord`, `recordId: "00162DE"`
- **Inconsistency in context.txt:** Apex class in §4.0 is `CustomRecordController` with method `getCustomRecordDetails`, but Aura descriptor in §6.0 is `c.CustomObjectController.getRecord` (different class name). HAR is authoritative.
- Response: `OwnerId: 005VICTIM`, `SSN: 000-75-7543` (tax compliance PII — SSN in tax context is extremely sensitive)
- Pattern 10.2: Parameter escalation (own session scope extension) — attacker uses their own valid session and substitutes `recordId` to extend their access scope to victim tax compliance records; no server-side ownership check in `without sharing` controller
- §8.0 RISK-SF-098/099: controller without `with sharing`; no ownership check; client-supplied `recordId` directly interpolated
**Consistency Guard:** All values from this folder's context.txt only.
