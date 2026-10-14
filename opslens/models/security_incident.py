from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


import uuid


@dataclass
class SecurityIncident:
    """
    Represents a security incident created from one or more alerts.
    """

    severity: str
    status: str
    title: str
    description: str

    user_id: str | None = None

    alert_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)

    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    incident_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )

    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "created_at": self.created_at.isoformat(),
            "severity": self.severity,
            "status": self.status,
            "title": self.title,
            "description": self.description,
            "user_id": self.user_id,
            "alert_ids": self.alert_ids,
            "event_ids": self.event_ids,
            "metadata": self.metadata

        }

incident = SecurityIncident(
        severity="HIGH",
        status="OPEN",
        title="Suspicious payment activity",
        description="Repeated payment failures followed by successful payment activity.",
        user_id="U102",
        alert_ids=["alert-123"],
        event_ids=["event-1", "event-2"],
        metadata={
            "source": "PAYMENT_FRAUD_DETECTION"
        }
)