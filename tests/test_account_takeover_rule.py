from datetime import datetime, timedelta, timezone

from opslens.detection.rules.account_takeover_rule import AccountTakeoverRule
from opslens.models.security_event import SecurityEvent


BASE_TIME = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_type,
    user_id="U102",
    seconds_after=0,
    ip_address="192.168.1.20",
    event_id=None,
):
    event = SecurityEvent(
        service="payment-service",
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        timestamp=BASE_TIME + timedelta(seconds=seconds_after),
    )

    if event_id is not None:
        event.event_id = event_id

    return event


def test_detects_possible_account_takeover():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", seconds_after=0, ip_address="192.168.1.20", event_id="E1"),
        make_event("LOGIN_SUCCESS", seconds_after=30, ip_address="192.168.1.21", event_id="E2"),
        make_event("PAYMENT_SUCCESS", seconds_after=60, event_id="E3"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.rule == "ACCOUNT_TAKEOVER_DETECTION"
    assert alert.severity == "CRITICAL"
    assert alert.user_id == "U102"
    assert alert.event_ids == ["E1", "E2", "E3"]
    assert alert.metadata["login_ip_count"] == 2
    assert set(alert.metadata["login_ips"]) == {
        "192.168.1.20",
        "192.168.1.21",
    }
    assert alert.metadata["payment_events"] == 1
    assert alert.metadata["account_takeover_indicator"] is True


def test_does_not_alert_with_fewer_than_two_successful_logins():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", ip_address="192.168.1.20"),
        make_event("PAYMENT_SUCCESS", seconds_after=10),
    ]

    assert rule.evaluate(events) == []


def test_does_not_alert_when_logins_use_same_ip():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", seconds_after=0, ip_address="192.168.1.20"),
        make_event("LOGIN_SUCCESS", seconds_after=10, ip_address="192.168.1.20"),
        make_event("PAYMENT_SUCCESS", seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_does_not_alert_without_payment_activity():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", seconds_after=0, ip_address="192.168.1.20"),
        make_event("LOGIN_SUCCESS", seconds_after=10, ip_address="192.168.1.21"),
        make_event("LOGIN_FAILED", seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_payment_failure_also_counts_as_payment_activity():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", seconds_after=0, ip_address="192.168.1.20"),
        make_event("LOGIN_SUCCESS", seconds_after=10, ip_address="192.168.1.21"),
        make_event("PAYMENT_FAILED", seconds_after=20),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].metadata["payment_events"] == 1


def test_ignores_events_without_user_id():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", user_id=None, ip_address="192.168.1.20"),
        make_event("LOGIN_SUCCESS", user_id=None, ip_address="192.168.1.21"),
        make_event("PAYMENT_SUCCESS", user_id=None),
    ]

    assert rule.evaluate(events) == []


def test_evaluates_users_independently():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", user_id="U102", seconds_after=0, ip_address="192.168.1.20"),
        make_event("LOGIN_SUCCESS", user_id="U102", seconds_after=10, ip_address="192.168.1.21"),
        make_event("PAYMENT_SUCCESS", user_id="U102", seconds_after=20),
        make_event("LOGIN_SUCCESS", user_id="U103", seconds_after=30, ip_address="192.168.1.30"),
        make_event("PAYMENT_SUCCESS", user_id="U103", seconds_after=40),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].user_id == "U102"


def test_ignores_missing_login_ip_addresses():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", seconds_after=0, ip_address="192.168.1.20"),
        make_event("LOGIN_SUCCESS", seconds_after=10, ip_address=None),
        make_event("PAYMENT_SUCCESS", seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_counts_multiple_payment_events():
    rule = AccountTakeoverRule()

    events = [
        make_event("LOGIN_SUCCESS", seconds_after=0, ip_address="192.168.1.20"),
        make_event("LOGIN_SUCCESS", seconds_after=10, ip_address="192.168.1.21"),
        make_event("PAYMENT_SUCCESS", seconds_after=20),
        make_event("PAYMENT_FAILED", seconds_after=30),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].metadata["payment_events"] == 2
