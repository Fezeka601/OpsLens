import math
import traceback
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, model_validator

from opslens.models.security_event import SecurityEvent

from opslens.database.event_repository import EventRepository
from opslens.database.alert_repository import AlertRepository
from opslens.database.incident_repository import IncidentRepository
from opslens.database.investigation_repository import (
    InvestigationRepository,
)
from opslens.database.response_repository import ResponseRepository

from opslens.investigation.incident_investigator import (
    IncidentInvestigator,
)
from opslens.detection.anomaly_detector import DetectionEngine

from opslens.detection.rules.brute_force_rule import BruteForceRule
from opslens.detection.rules.payment_fraud_rule import PaymentFraudRule
from opslens.detection.rules.account_takeover_rule import AccountTakeoverRule
from opslens.detection.rules.unusual_payment_amount_rule import (
    UnusualPaymentAmountRule,
)
from opslens.detection.rules.rapid_transactions_rule import (
    RapidTransactionsRule,
)
from opslens.detection.rules.suspicious_login_rule import (
    SuspiciousLoginRule,
)
from opslens.detection.rules.unauthorized_access_rule import (
    UnauthorizedAccessRule,
)
from opslens.detection.rules.privilege_abuse_rule import PrivilegeAbuseRule

from opslens.ingestion.event_ingestor import EventIngestor
from opslens.normalization.event_normalizer import EventNormalizer
from opslens.incidents.incident_correlator import IncidentCorrelator
from opslens.incidents.incident_manager import IncidentManager
from opslens.response.response_engine import IncidentResponseEngine


# --------------------------------------------------
# Supported event types
# --------------------------------------------------

EventType = Literal[
    "LOGIN_FAILED",
    "LOGIN_SUCCESS",
    "PAYMENT_FAILED",
    "PAYMENT_SUCCESS",
    "FRAUD_CHECK",
    "ACCESS_DENIED",
    "PRIVILEGE_VIOLATION",
]


# --------------------------------------------------
# Request models
# --------------------------------------------------

class ResponseActionStatusUpdate(BaseModel):
    status: Literal[
        "UNDER_REVIEW",
        "APPROVED",
        "COMPLETED",
    ]


class SecurityEventCreate(BaseModel):
    # Optional client-supplied ID makes retries identifiable.
    event_id: str | None = Field(default=None, min_length=1)

    service: str = Field(min_length=1, pattern=r".*\S.*")
    event_type: EventType

    user_id: str | None = None
    transaction_id: str | None = None
    ip_address: str | None = None
    timestamp: datetime | None = None

    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_payment_amount(self):
        if self.event_type != "PAYMENT_SUCCESS":
            return self

        amount = self.metadata.get("amount")

        if amount is None or isinstance(amount, bool):
            raise ValueError(
                "PAYMENT_SUCCESS requires a numeric amount."
            )

        try:
            numeric_amount = float(amount)
        except (TypeError, ValueError, OverflowError):
            raise ValueError(
                "Payment amount must be numeric."
            ) from None

        if not math.isfinite(numeric_amount):
            raise ValueError(
                "Payment amount must be finite."
            )

        if numeric_amount < 0:
            raise ValueError(
                "Payment amount cannot be negative."
            )

        self.metadata["amount"] = numeric_amount
        return self


# --------------------------------------------------
# FastAPI application
# --------------------------------------------------

app = FastAPI(
    title="OpsLens Security API",
    description="Security monitoring and incident investigation API",
    version="1.0.0",
)


# --------------------------------------------------
# Repositories and processing components
# --------------------------------------------------

event_repository = EventRepository()
alert_repository = AlertRepository()
incident_repository = IncidentRepository()
investigation_repository = InvestigationRepository()
response_repository = ResponseRepository()

event_ingestor = EventIngestor()
event_normalizer = EventNormalizer()

incident_correlator = IncidentCorrelator()
incident_manager = IncidentManager()
incident_investigator = IncidentInvestigator()
incident_response_engine = IncidentResponseEngine()

detection_engine = DetectionEngine(
    rules=[
        BruteForceRule(),
        PaymentFraudRule(),
        AccountTakeoverRule(),
        UnusualPaymentAmountRule(),
        RapidTransactionsRule(),
        SuspiciousLoginRule(),
        UnauthorizedAccessRule(),
        PrivilegeAbuseRule(),
    ]
)


# --------------------------------------------------
# Helper functions
# --------------------------------------------------

def alert_signature(rule, severity, event_ids, message):
    """Create a consistent signature to prevent duplicate alerts."""
    return (
        rule,
        severity,
        tuple(sorted(str(item) for item in (event_ids or []))),
        message,
    )


def serialize_incident(incident):
    """Convert an incident into a response-friendly dictionary."""
    if hasattr(incident, "to_dict"):
        return jsonable_encoder(incident.to_dict())

    if hasattr(incident, "model_dump"):
        return jsonable_encoder(incident.model_dump())

    if hasattr(incident, "__dict__"):
        return jsonable_encoder(vars(incident))

    return jsonable_encoder(incident)


def serialize_alert(alert):
    """Convert an alert into a response-friendly dictionary."""
    if hasattr(alert, "to_dict"):
        return jsonable_encoder(alert.to_dict())

    if hasattr(alert, "model_dump"):
        return jsonable_encoder(alert.model_dump())

    if hasattr(alert, "__dict__"):
        return jsonable_encoder(vars(alert))

    return jsonable_encoder(alert)


# --------------------------------------------------
# Health
# --------------------------------------------------

@app.get("/health")
def health_check():
    return {"status": "healthy"}


# --------------------------------------------------
# Events
# --------------------------------------------------

@app.get("/events")
def get_events(
    limit: int = Query(default=100, ge=1, le=500),
):
    try:
        return event_repository.get_all(limit=limit)

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e


@app.post("/events", status_code=201)
def create_event(request: SecurityEventCreate):
    try:
        # 1. Ingest and normalize the incoming event.
        event = event_ingestor.ingest(request.model_dump())
        event = event_normalizer.normalize(event)

        # 2. Save the event and check whether it was inserted.
        saved = event_repository.save(event)

        # A repeated event ID must not run detection again.
        if not saved:
            return JSONResponse(
                status_code=200,
                content={
                    "event_id": event.event_id,
                    "message": (
                        "Event already exists; duplicate submission ignored."
                    ),
                    "duplicate": True,
                    "detection": {
                        "matches_found": 0,
                        "new_alerts_saved": 0,
                        "alerts": [],
                    },
                    "incidents_created": 0,
                    "incidents": [],
                },
            )

        # 3. Load stored events for pattern-based detection.
        event_rows = event_repository.get_all(limit=500)
        historical_events = []

        for row in event_rows:
            timestamp = row["timestamp"]

            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(
                    timestamp.replace("Z", "+00:00")
                )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            historical_events.append(
                SecurityEvent(
                    event_id=str(row["event_id"]),
                    timestamp=timestamp,
                    service=row["service"],
                    event_type=row["event_type"],
                    user_id=row["user_id"],
                    transaction_id=row["transaction_id"],
                    ip_address=row["ip_address"],
                    metadata=row["metadata"] or {},
                )
            )

        # Ensure the submitted event is evaluated.
        known_event_ids = {
            item.event_id for item in historical_events
        }

        if event.event_id not in known_event_ids:
            historical_events.append(event)

        historical_events.sort(key=lambda item: item.timestamp)

        # 4. Run all detection rules.
        detected_alerts = detection_engine.detect(historical_events)

        # Keep alerts associated with the submitted event.
        relevant_alerts = [
            alert
            for alert in detected_alerts
            if event.event_id in {
                str(event_id)
                for event_id in (alert.event_ids or [])
            }
        ]

        # 5. Load previously stored alerts.
        existing_alert_rows = alert_repository.get_all(limit=10000)

        known_signatures = {
            alert_signature(
                row["rule"],
                row["severity"],
                row["event_ids"],
                row["message"],
            )
            for row in existing_alert_rows
        }

        # 6. Save only new alerts relevant to this event.
        newly_saved_alerts = []

        for alert in relevant_alerts:
            signature = alert_signature(
                alert.rule,
                alert.severity,
                alert.event_ids,
                alert.message,
            )

            if signature in known_signatures:
                continue

            alert_repository.save(alert)
            known_signatures.add(signature)
            newly_saved_alerts.append(alert)

        # 7. Correlate new alerts into incident groups.
        incident_groups = incident_correlator.correlate(
            newly_saved_alerts
        )

        # 8. Create incidents and generate response actions.
        created_incidents = []

        if incident_groups:
            incidents = incident_manager.create_incidents(
                incident_groups
            )

            for incident in incidents:
                incident_repository.save(incident)

                incident_alert_ids = {
                    str(alert_id)
                    for alert_id in (incident.alert_ids or [])
                }

                for alert in newly_saved_alerts:
                    if str(alert.alert_id) not in incident_alert_ids:
                        continue

                    actions = incident_response_engine.generate_actions(
                        incident,
                        alert,
                    )

                    for action in actions:
                        response_repository.save_action(
                            incident_id=str(incident.incident_id),
                            alert_id=str(alert.alert_id),
                            action=action,
                        )

                created_incidents.append(
                    serialize_incident(incident)
                )

        # 9. Build the response.
        result = event.to_dict()

        result["detection"] = {
            "matches_found": len(relevant_alerts),
            "new_alerts_saved": len(newly_saved_alerts),
            "alerts": [
                {
                    "alert_id": str(alert.alert_id),
                    "rule": alert.rule,
                    "severity": alert.severity,
                    "message": alert.message,
                }
                for alert in newly_saved_alerts
            ],
        }

        result["incidents_created"] = len(created_incidents)
        result["incidents"] = created_incidents

        return jsonable_encoder(result)

    except HTTPException:
        raise

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail="An unexpected internal error occurred.",
        ) from e


# --------------------------------------------------
# Alerts
# --------------------------------------------------

@app.get("/alerts")
def get_alerts(
    limit: int = Query(default=100, ge=1, le=500),
):
    try:
        return alert_repository.get_all(limit=limit)

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e


# --------------------------------------------------
# Incidents
# --------------------------------------------------

@app.get("/incidents")
def get_incidents(
    limit: int = Query(default=100, ge=1, le=500),
):
    try:
        return incident_repository.get_all(limit=limit)

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str):
    try:
        incident = incident_repository.get_by_id(incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        return incident

    except HTTPException:
        raise

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e


# --------------------------------------------------
# Incident investigations
# --------------------------------------------------

@app.post("/incidents/{incident_id}/investigation")
def run_incident_investigation(incident_id: str):
    try:
        incident = incident_repository.get_model_by_id(incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        events = event_repository.get_by_ids(incident.event_ids)

        if not events:
            raise HTTPException(
                status_code=422,
                detail="No stored events were found for this incident",
            )

        investigation = incident_investigator.investigate(
            incident,
            events,
        )

        investigation_id = investigation_repository.save(investigation)

        return jsonable_encoder({
            "investigation_id": investigation_id,
            **investigation,
        })

    except HTTPException:
        raise

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e


@app.get("/incidents/{incident_id}/investigation")
def get_incident_investigations(incident_id: str):
    try:
        incident = incident_repository.get_by_id(incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        investigations = (
            investigation_repository.get_by_incident_id(incident_id)
        )

        return {
            "incident_id": incident_id,
            "investigation_count": len(investigations),
            "investigations": investigations,
        }

    except HTTPException:
        raise

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e


# --------------------------------------------------
# Incident response actions
# --------------------------------------------------

@app.get("/incidents/{incident_id}/response-actions")
def get_incident_response_actions(incident_id: str):
    try:
        incident = incident_repository.get_by_id(incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        actions = response_repository.get_by_incident_id(incident_id)

        return {
            "incident_id": incident_id,
            "action_count": len(actions),
            "actions": actions,
        }

    except HTTPException:
        raise

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e


@app.patch(
    "/incidents/{incident_id}/response-actions/"
    "{response_action_id}/status"
)
def update_response_action_status(
    incident_id: str,
    response_action_id: str,
    request: ResponseActionStatusUpdate,
):
    try:
        incident = incident_repository.get_by_id(incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found",
            )

        updated = response_repository.update_status(
            incident_id=incident_id,
            response_action_id=response_action_id,
            status=request.status,
        )

        if not updated:
            raise HTTPException(
                status_code=404,
                detail="Response action not found for this incident",
            )

        return {
            "message": "Response action status updated successfully",
            "incident_id": incident_id,
            "response_action_id": response_action_id,
            "status": request.status,
        }

    except HTTPException:
        raise

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail=f"{type(e).__name__}: {e}",
        ) from e