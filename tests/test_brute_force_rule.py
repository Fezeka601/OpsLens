from datetime import datetime, timedelta, timezone

import pytest

from opslens.detection.rules.brute_force_rule import BruteForceRule
from opslens.models.security_event import SecurityEvent


BASE_TIME = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_type="LOGIN_FAILED",
    user_id="U102",
    seconds_after=0,
    ip_address="192.168.1.20",
    event_id=None,
):
    event = SecurityEvent(
        service="auth-service",
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        timestamp=BASE_TIME + timedelta(seconds=seconds_after),
    )

    if event_id is not None:
        event.event_id = event_id

    return event


def test_detects_failed_logins_at_threshold():
    rule = BruteForceRule(threshold=3, window_seconds=300)

    events = [
        make_event(seconds_after=0, event_id="E1"),
        make_event(seconds_after=30, event_id="E2"),
        make_event(seconds_after=60, event_id="E3"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "BRUTE_FORCE_DETECTION"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].user_id == "U102"
    assert alerts[0].event_ids == ["E1", "E2", "E3"]
    assert alerts[0].metadata["failed_attempts"] == 3
    assert alerts[0].metadata["window_seconds"] == 300


def test_does_not_alert_below_threshold():
    rule = BruteForceRule(threshold=3)

    events = [
        make_event(seconds_after=0),
        make_event(seconds_after=30),
    ]

    assert rule.evaluate(events) == []


def test_does_not_alert_when_failures_are_outside_window():
    rule = BruteForceRule(threshold=3, window_seconds=60)

    events = [
        make_event(seconds_after=0),
        make_event(seconds_after=30),
        make_event(seconds_after=61),
    ]

    assert rule.evaluate(events) == []


def test_ignores_non_failed_login_events():
    rule = BruteForceRule(threshold=3)

    events = [
        make_event(event_type="LOGIN_SUCCESS", seconds_after=0),
        make_event(event_type="LOGIN_SUCCESS", seconds_after=10),
        make_event(event_type="LOGIN_SUCCESS", seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_ignores_failed_logins_without_user_id():
    rule = BruteForceRule(threshold=3)

    events = [
        make_event(user_id=None, seconds_after=0),
        make_event(user_id=None, seconds_after=10),
        make_event(user_id=None, seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_groups_failed_logins_by_user():
    rule = BruteForceRule(threshold=3)

    events = [
        make_event(user_id="U102", seconds_after=0),
        make_event(user_id="U102", seconds_after=10),
        make_event(user_id="U103", seconds_after=20),
        make_event(user_id="U103", seconds_after=30),
    ]

    assert rule.evaluate(events) == []


def test_detects_users_independently():
    rule = BruteForceRule(threshold=3)

    events = [
        make_event(user_id="U102", seconds_after=0),
        make_event(user_id="U103", seconds_after=1),
        make_event(user_id="U102", seconds_after=2),
        make_event(user_id="U103", seconds_after=3),
        make_event(user_id="U102", seconds_after=4),
        make_event(user_id="U103", seconds_after=5),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert {alert.user_id for alert in alerts} == {"U102", "U103"}


def test_sorts_events_chronologically():
    rule = BruteForceRule(threshold=3)

    events = [
        make_event(seconds_after=20, event_id="E3"),
        make_event(seconds_after=0, event_id="E1"),
        make_event(seconds_after=10, event_id="E2"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == ["E1", "E2", "E3"]


def test_includes_unique_source_ips():
    rule = BruteForceRule(threshold=3)

    events = [
        make_event(seconds_after=0, ip_address="192.168.1.21"),
        make_event(seconds_after=10, ip_address="192.168.1.20"),
        make_event(seconds_after=20, ip_address="192.168.1.21"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].metadata["source_ips"] == [
        "192.168.1.20",
        "192.168.1.21",
    ]


@pytest.mark.parametrize("threshold", [0, -1])
def test_rejects_invalid_threshold(threshold):
    with pytest.raises(ValueError, match="threshold must be at least 1"):
        BruteForceRule(threshold=threshold)


@pytest.mark.parametrize("window_seconds", [0, -1])
def test_rejects_invalid_window(window_seconds):
    with pytest.raises(
        ValueError,
        match="window_seconds must be at least 1",
    ):
        BruteForceRule(window_seconds=window_seconds)
