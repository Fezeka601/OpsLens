from dataclasses import dataclass

from opslens.models.security_event import SecurityEvent


@dataclass
class CorrelationResult:
    events: list[SecurityEvent]
    relationships: list[str]


class EventCorrelator:

    def correlate(
        self,
        events: list[SecurityEvent]
    ) -> list[CorrelationResult]:

        results = []
        processed_events = set()

        for event in events:

            if event.event_id in processed_events:
                continue

            related_events = [event]
            relationships = []

            processed_events.add(event.event_id)

            for other_event in events:

                if other_event.event_id in processed_events:
                    continue

                relationship = self._find_relationship(
                    event,
                    other_event
                )

                if relationship:

                    related_events.append(other_event)
                    relationships.append(relationship)

                    processed_events.add(
                        other_event.event_id
                    )

            results.append(
                CorrelationResult(
                    events=related_events,
                    relationships=relationships
                )
            )

        return results

    def _find_relationship(
        self,
        event: SecurityEvent,
        other_event: SecurityEvent
    ) -> str | None:

        if (
            event.transaction_id
            and event.transaction_id == other_event.transaction_id
        ):
            return "SAME_TRANSACTION"

        if (
            event.user_id
            and event.user_id == other_event.user_id
        ):
            return "SAME_USER"

        if (
            event.ip_address
            and event.ip_address == other_event.ip_address
        ):
            return "SAME_SOURCE_IP"

        return None