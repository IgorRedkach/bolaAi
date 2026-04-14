# Analysis Explanation
**Folder:** SF-0050-PARKING | **Context source:** This folder's context.txt only.
- System: ParkIQ Management API, Parking/Smart City, OWD: Private on CustomRecord
- Host: `3690c3b3.lightning.force.com`, token: `00D3690C3B3!AR3690c3b3...`
- Descriptor: `c.CustomObjectController.getRecord`, `recordId: "001C3B3"`
- Response: `OwnerId: 005VICTIM`, `SSN: 000-22-9665`
- RISK-SF-050 (no `with sharing`), RISK-SF-051 (no ownership predicate)
- Pattern 1.5: Cross-tenant/cross-user access via direct ID substitution. No tenant isolation mechanism in the controller.
**Consistency Guard:** All values from this folder's context.txt only.
