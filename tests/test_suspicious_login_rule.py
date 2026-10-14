from datetime import datetime, timedelta, timezone

from opslens.detection.rules.suspicious_login_rule import (
    SuspiciousLoginRule,
)
from opslens.models.security_event import SecurityEvent


BASE_TIME = datetime(
    2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc
)


def make_event(
    event_type="LOGIN_SUCCESS",
    user_id="U101",
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
    )

    if event_id is not None:
        event.event_id = event_id

    return event


def test_detects_login_from_new_ip():
    rule = SuspiciousLoginRule()

    events = [
        make_event(ip_address="192.168.1.10", event_id="E1"),
        make_event(
            ip_address="192.168.1.20",
            minutes_after=1,
            event_id="E2",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "SUSPICIOUS_LOGIN_DETECTION"
    assert alerts[0].severity == "MEDIUM"
    assert alerts[0].user_id == "U101"
    assert alerts[0].event_ids == ["E2"]


def test_does_not_alert_for_only_one_login():
    rule = SuspiciousLoginRule()

    alerts = rule.evaluate([
        make_event(ip_address="192.168.1.10"),
    ])

    assert alerts == []


def test_does_not_alert_for_repeated_logins_from_same_ip():
    rule = SuspiciousLoginRule()

    events = [
        make_event(ip_address="192.168.1.10"),
        make_event(
            ip_address="192.168.1.10",
            minutes_after=1,
        ),
        make_event(
            ip_address="192.168.1.10",
            minutes_after=2,
        ),
    ]

    assert rule.evaluate(events) == []


def test_ignores_non_successful_login_events():
    rule = SuspiciousLoginRule()

    events = [
        make_event(ip_address="192.168.1.10"),
        make_event(
            event_type="LOGIN_FAILED",
            ip_address="192.168.1.20",
            minutes_after=1,
        ),
    ]

    assert rule.evaluate(events) == []


def test_does_not_mix_events_from_different_users():
    rule = SuspiciousLoginRule()

    events = [
        make_event(
            user_id="U101",
            ip_address="192.168.1.10",
        ),
        make_event(
            user_id="U202",
            ip_address="192.168.1.20",
            minutes_after=1,
        ),
    ]

    assert rule.evaluate(events) == []


def test_detects_new_ips_for_users_independently():
    rule = SuspiciousLoginRule()

    events = [
        make_event(
            user_id="U101",
            ip_address="192.168.1.10",
        ),
        make_event(
            user_id="U202",
            ip_address="10.0.0.1",
            minutes_after=1,
        ),
        make_event(
            user_id="U101",
            ip_address="192.168.1.20",
            minutes_after=2,
        ),
        make_event(
            user_id="U202",
            ip_address="10.0.0.2",
            minutes_after=3,
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert {alert.user_id for alert in alerts} == {
        "U101",
        "U202",
    }


def test_ignores_events_without_user_id():
    rule = SuspiciousLoginRule()

    events = [
        make_event(user_id=None, ip_address="192.168.1.10"),
        make_event(
            user_id=None,
            ip_address="192.168.1.20",
            minutes_after=1,
        ),
    ]

    assert rule.evaluate(events) == []


def test_ignores_missing_ip_addresses():
    rule = SuspiciousLoginRule()

    events = [
        make_event(ip_address="192.168.1.10", event_id="E1"),
        make_event(
            ip_address=None,
            minutes_after=1,
            event_id="E2",
        ),
        make_event(
            ip_address="192.168.1.20",
            minutes_after=2,
            event_id="E3",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == ["E3"]
    assert alerts[0].metadata["new_ip_address"] == "192.168.1.20"


def test_alert_metadata_contains_known_ip_and_anomaly_flag():
    rule = SuspiciousLoginRule()

    events = [
        make_event(ip_address="192.168.1.10", event_id="E1"),
        make_event(
            ip_address="192.168.1.20",
            minutes_after=1,
            event_id="E2",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    metadata = alerts[0].metadata

    assert metadata["new_ip_address"] == "192.168.1.20"
    assert "192.168.1.10" in metadata["known_ip_addresses"]
    assert metadata["login_anomaly"] is True


def test_creates_an_alert_for_each_subsequent_new_ip():
    rule = SuspiciousLoginRule()

    events = [
        make_event(ip_address="192.168.1.10", event_id="E1"),
        make_event(
            ip_address="192.168.1.20",
            minutes_after=1,
            event_id="E2",
        ),
        make_event(
            ip_address="192.168.1.30",
            minutes_after=2,
            event_id="E3",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert alerts[0].event_ids == ["E2"]
    assert alerts[1].event_ids == ["E3"]
    assert "192.168.1.10" in alerts[1].metadata["known_ip_addresses"]
    assert "192.168.1.20" in alerts[1].metadata["known_ip_addresses"]
