OpsLens API Test Results

Project: OpsLens Security Monitoring API
Test date: 11 October 2026
Testing tool: Swagger UI / FastAPI OpenAPI documentation
Base URL: http://127.0.0.1:8000
Overall status: All currently identified API endpoints tested successfully

1. Health and Events

Endpoint

Test performed

Expected result

Result

GET /health

Check API health

200 OK

PASS

GET /events

Retrieve events with a valid limit

200 OK

PASS

GET /events

Supply limit=0

422 Unprocessable Entity

PASS

POST /events

Submit an empty request body

422 Unprocessable Entity

PASS

POST /events

Submit an invalid event type

422 Unprocessable Entity

PASS

POST /events

Submit an invalid timestamp

422 Unprocessable Entity

PASS

POST /events

Omit the required service field

422 Unprocessable Entity

PASS

POST /events

Submit a negative payment amount

422 Unprocessable Entity

PASS

POST /events

Omit metadata. Amount for PAYMENT_SUCCESS

422 Unprocessable Entity

PASS

POST /events

Submit a duplicate event ID

409 Conflict

PASS

2. Alerts and Incidents

Endpoint

Test performed

Expected result

Result

GET /alerts

Retrieve stored security alerts

200 OK

PASS

GET /incidents

Retrieve stored incidents

200 OK

PASS

GET /incidents/{incident_id}

Retrieve an existing incident

200 OK

PASS

GET /incidents/{incident_id}

Submit a malformed incident UUID

400 Bad Request

PASS

GET /incidents/{incident_id}

Submit a valid UUID for a nonexistent incident

404 Not Found

PASS

3. Investigations

Endpoint

Test performed

Expected result

Result

POST /incidents/{incident_id}/investigation

Investigate a nonexistent incident

404 Not Found

PASS

POST /incidents/{incident_id}/investigation

Create an investigation for an existing incident

200 OK

PASS

GET /incidents/{incident_id}/investigation

Submit a malformed incident UUID

400 Bad Request

PASS

GET /incidents/{incident_id}/investigation

Request investigations for a nonexistent incident

404 Not Found

PASS

GET /incidents/{incident_id}/investigation

Retrieve a saved investigation

200 OK

PASS

4. Response Actions

Endpoint

Test performed

Expected result

Result

GET /incidents/{incident_id}/response-actions

Request actions for a nonexistent incident

404 Not Found

PASS

GET /incidents/{incident_id}/response-actions

Retrieve actions for an existing incident

200 OK

PASS

PATCH /incidents/{incident_id}/response-actions/{response_action_id}/status

Submit an invalid status

422 Unprocessable Entity

PASS

PATCH /incidents/{incident_id}/response-actions/{response_action_id}/status

Update an action for a nonexistent incident

404 Not Found

PASS

PATCH /incidents/{incident_id}/response-actions/{response_action_id}/status

Update an existing action to APPROVED

200 OK

PASS

GET /incidents/{incident_id}/response-actions

Verify the updated status was persisted

200 OK; status is APPROVED

PASS

5. Investigation and Response-Action Data Verification

The following real incident was used to verify successful workflows:

Incident ID: 66b3ce20-0c0c-40f2-91fb-1da91e3b1f33

Title: Suspicious payment activity

Severity: HIGH

Initial status: OPEN

Response actions retrieved: 3

Status update verified: RECOMMENDED → APPROVED

The investigation was created and subsequently retrieved. The response-action status update was also retrieved successfully, confirming that the new status persisted.

6. Summary

The identified API routes have passed their recorded functional and validation checks, including successful retrieval, invalid input handling, missing-resource handling, investigation creation, and response-action status updates.

Next milestone: Connect the OpsLens frontend to the API and test the integrated application.

Scope note: These results document the tests performed so far. They do not constitute exhaustive security testing, load testing, or full frontend integration testing.

Idempotency Test — Duplicate Event Submission

Status: PASS

Submitted a security event using a valid UUID.

Confirmed the event was saved successfully to PostgreSQL.

Resubmitted the same event with the same UUID.

The API returned HTTP 200 with duplicate: true.

PostgreSQL confirmed exactly one record exists for the event ID.

No alerts or incidents were created for this test event.

Conclusion: Repeated submissions with the same event ID are ignored, preventing duplicate event records and repeated processing.