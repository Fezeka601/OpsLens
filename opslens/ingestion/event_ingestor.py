from datetime import datetime
from typing import Any

from opslens.models.security_event import SecurityEvent


class EventIngestor:

    def ingest(self, event_data: dict[str, Any]) -> SecurityEvent:
        """
        Convert incoming event data into a SecurityEvent.

        Preserve a supplied event ID and timestamp when available.
        Generate a new event ID when one is not supplied.
        """

        timestamp = event_data.get("timestamp")

        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

        event_fields = {
            "service": event_data.get("service"),
            "event_type": event_data.get("event_type"),
            "user_id": event_data.get("user_id"),
            "transaction_id": event_data.get("transaction_id"),
            "ip_address": event_data.get("ip_address"),
            "metadata": event_data.get("metadata") or {},
        }

        if timestamp is not None:
            event_fields["timestamp"] = timestamp

        event_id = event_data.get("event_id")
        if event_id:
            event_fields["event_id"] = str(event_id)

        event = SecurityEvent(**event_fields)

        print("Security event ingested:")
        print(event.to_dict())

        return event
