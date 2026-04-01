# Salesforce HAR-Like Security Capture (Benchmark Fixture)

Source type: HAR-derived notes from browser/API traffic.

## Observed Operations

1. `POST /services/data/v60.0/graphql`
   - Operation: `getCaseCommentCount`
   - Variables include: `recordId` (Case ID)
   - No explicit ownership check documented in resolver notes.

2. `POST /services/data/v60.0/graphql`
   - Operation: `getCaseComments`
   - Variables include: `recordId` (Case ID)
   - Response fields observed: comment body (`Body__c`), author data, publish status, timestamps.
   - No explicit ownership check documented in resolver notes.

3. `GET /services/data/v60.0/sobjects/Case/500cT00000BPDwjQAH`
   - Returned fields observed: `ContactEmail`, `SuppliedEmail`, `SuppliedName`, `SuppliedPhone`, `SuppliedCompany`.
   - No explicit object-level authorization statement in this capture.

4. `POST /aura?r=15&aura.ApexAction.execute=1`
   - Action family observed: `updateRecord` with `recordId` and `recordInput`.
   - Example editable field in capture: `Priority`.
   - No explicit ownership or assignment check documented in action notes.
   - No explicit FLS enforcement statement documented in these notes.

5. `GET /services/data/v60.0/sobjects/Account/001cT00000DQOooQAH`
   - Returned custom fields include `AccessRestrictions__c`, `SecuredEnvironment__c`.

## Data model notes

- `CaseComment__c` appears as a custom object in this environment.
- It is not documented here whether `CaseComment__c` sharing inherits from parent `Case` or has independent OWD/sharing.

## Constraints

- This fixture is Salesforce/Aura/GraphQL-oriented and **not** a generic SQL/REST-only system.
- Findings must stay grounded to the operations listed above.
