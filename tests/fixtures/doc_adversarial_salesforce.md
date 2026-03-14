# GovCRM Salesforce Integration

## Overview
GovCRM integrates with Salesforce for accounts, contacts, and cases. Custom Apex and APIs run SOQL queries.

## Authentication
- OAuth2 to Salesforce. User context determines which records are visible.

## SOQL Examples (from integration docs)
- `SELECT Id, Name, Industry FROM Account`
- `SELECT Id, Subject, Status, (SELECT Id, Comment FROM CaseComments) FROM Case WHERE Status = 'Open'`
- `SELECT Id, Amount, CloseDate FROM Opportunity`

## Sharing Model
- Account: Organization-wide default is "Private". Cases inherit from Account.
- Documentation does not mention `WITH SECURITY_ENFORCED` or `UserRecordAccess` in the example queries.
- No explicit statement that queries filter by OwnerId or sharing rules.

## API Endpoints
- **GET /api/sf/accounts** — Proxies to Salesforce. Runs SOQL internally. No documented filter.
- **GET /api/sf/cases/{caseId}** — Returns case by ID. No ownership check documented.
