from datetime import datetime, timedelta, timezone

from opslens.detection.rules.unauthorized_access_rule import (
    UnauthorizedAccessRule,
)
from opslens.models.security_event import SecurityEvent


BASE_TIME = datetime(
    2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc
)


def make_event(
    event_type="ACCESS_DENIED",
    user_id="U101",
    resource="/admin/users",
    ip_address="192.168.1.10",
    minutes_after=0,
    event_id=None,
):
    event = SecurityEvent(
        service="auth-service",
        event_type=event_type,
        user_id=user_id,
        timestamp=BASE_TIME + timedelta(minutes=minutes_after),
        ip_address=ip_address,
        metadata={"resource": resource} if resource else {},
    )

    if event_id is not None:
        event.event_id = event_id

    return event


def test_detects_single_unauthorized_access_attempt():
    rule = UnauthorizedAccessRule()

    alerts = rule.evaluate([make_event(event_id="E1")])

    assert len(alerts) == 1
    assert alerts[0].rule == "UNAUTHORIZED_ACCESS_DETECTION"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].user_id == "U101"
    assert alerts[0].event_ids == ["E1"]


def test_groups_multiple_denied_attempts_for_same_user():
    rule = UnauthorizedAccessRule()

    events = [
        make_event(event_id="E1"),
        make_event(
            resource="/admin/settings",
            minutes_after=1,
            event_id="E2",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == ["E1", "E2"]
    assert alerts[0].metadata["denied_attempts"] == 2


def test_creates_separate_alerts_for_different_users():
    rule = UnauthorizedAccessRule()

    events = [
        make_event(user_id="U101", event_id="E1"),
        make_event(
            user_id="U202",
            ip_address="192.168.1.20",
            minutes_after=1,
            event_id="E2",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert {alert.user_id for alert in alerts} == {"U101", "U202"}


def test_ignores_events_that_are_not_access_denied():
    rule = UnauthorizedAccessRule()

    events = [
        make_event(event_type="LOGIN_SUCCESS"),
        make_event(event_type="ACCESS_GRANTED", minutes_after=1),
    ]

    assert rule.evaluate(events) == []


def test_ignores_events_without_user_id():
    rule = UnauthorizedAccessRule()

    events = [
        make_event(user_id=None, event_id="E1"),
        make_event(user_id=None, minutes_after=1, event_id="E2"),
    ]

    assert rule.evaluate(events) == []


def test_metadata_contains_unique_resources_and_source_ips():
    rule = UnauthorizedAccessRule()

    events = [
        make_event(
            resource="/admin/users",
            ip_address="192.168.1.10",
            event_id="E1",
        ),
        make_event(
            resource="/admin/users",
            ip_address="192.168.1.10",
            minutes_after=1,
            event_id="E2",
        ),
        make_event(
            resource="/admin/settings",
            ip_address="192.168.1.20",
            minutes_after=2,
            event_id="E3",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    metadata = alerts[0].metadata

    assert metadata["denied_attempts"] == 3
    assert set(metadata["resources"]) == {
        "/admin/users",
        "/admin/settings",
    }
    assert set(metadata["source_ips"]) == {
        "192.168.1.10",
        "192.168.1.20",
    }


def test_handles_missing_resource_and_ip_address():
    rule = UnauthorizedAccessRule()

    events = [
        make_event(
            resource=None,
            ip_address=None,
            event_id="E1",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].metadata["denied_attempts"] == 1
    assert alerts[0].metadata["resources"] == []
    assert alerts[0].metadata["source_ips"] == []


def test_preserves_event_ids_for_all_denied_attempts():
    rule = UnauthorizedAccessRule()

    events = [
        make_event(event_id="E1"),
        make_event(minutes_after=1, event_id="E2"),
        make_event(minutes_after=2, event_id="E3"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == ["E1", "E2", "E3"]
