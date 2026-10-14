from datetime import datetime, timezone

from opslens.models.security_event import SecurityEvent


class EventNormalizer:

    def normalize(self, event: SecurityEvent) -> SecurityEvent:
        """
        Normalize a SecurityEvent before it enters the
        correlation and detection pipeline.
        """

        event.service = event.service.strip().lower()
        event.event_type = event.event_type.strip().upper()

        if event.user_id:
            event.user_id = event.user_id.strip()

        if event.transaction_id:
            event.transaction_id = event.transaction_id.strip()

        if event.ip_address:
            event.ip_address = event.ip_address.strip()

        # Ensure the timestamp is timezone-aware.
        if event.timestamp.tzinfo is None:
            event.timestamp = event.timestamp.replace(
                tzinfo=timezone.utc
            )

        # Add normalization metadata.
        event.metadata["normalized"] = True
        event.metadata["normalized_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        return event