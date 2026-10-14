from datetime import datetime, timedelta, timezone

import pytest

from opslens.detection.rules.payment_fraud_rule import PaymentFraudRule
from opslens.models.security_event import SecurityEvent


BASE_TIME = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_type,
    user_id="U102",
    transaction_id="TX9001",
    seconds_after=0,
    ip_address="192.168.1.20",
    event_id=None,
):
    event = SecurityEvent(
        service="payment-service",
        event_type=event_type,
        user_id=user_id,
        transaction_id=transaction_id,
        ip_address=ip_address,
        timestamp=BASE_TIME + timedelta(seconds=seconds_after),
    )

    if event_id is not None:
        event.event_id = event_id

    return event


def test_detects_suspicious_payment_sequence():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0, event_id="E1"),
        make_event("PAYMENT_FAILED", seconds_after=30, event_id="E2"),
        make_event("FRAUD_CHECK", seconds_after=45, event_id="E3"),
        make_event("PAYMENT_SUCCESS", seconds_after=60, event_id="E4"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.rule == "PAYMENT_FRAUD_DETECTION"
    assert alert.severity == "HIGH"
    assert alert.user_id == "U102"
    assert alert.event_ids == ["E1", "E2", "E3", "E4"]
    assert alert.metadata["failed_payments"] == 2
    assert alert.metadata["fraud_checks"] == 1
    assert alert.metadata["successful_payments"] == 1
    assert alert.metadata["transaction_id"] == "TX9001"
    assert alert.metadata["window_seconds"] == 300


def test_does_not_alert_with_only_one_failed_payment():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0),
        make_event("FRAUD_CHECK", seconds_after=10),
        make_event("PAYMENT_SUCCESS", seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_does_not_alert_without_fraud_check():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0),
        make_event("PAYMENT_FAILED", seconds_after=10),
        make_event("PAYMENT_SUCCESS", seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_does_not_alert_without_successful_payment():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0),
        make_event("PAYMENT_FAILED", seconds_after=10),
        make_event("FRAUD_CHECK", seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_does_not_combine_different_transactions():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", transaction_id="TX1", seconds_after=0),
        make_event("PAYMENT_FAILED", transaction_id="TX1", seconds_after=10),
        make_event("FRAUD_CHECK", transaction_id="TX2", seconds_after=20),
        make_event("PAYMENT_SUCCESS", transaction_id="TX1", seconds_after=30),
    ]

    assert rule.evaluate(events) == []


def test_does_not_combine_different_users():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", user_id="U102", seconds_after=0),
        make_event("PAYMENT_FAILED", user_id="U102", seconds_after=10),
        make_event("FRAUD_CHECK", user_id="U103", seconds_after=20),
        make_event("PAYMENT_SUCCESS", user_id="U102", seconds_after=30),
    ]

    assert rule.evaluate(events) == []


def test_ignores_events_missing_user_or_transaction_id():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", transaction_id=None, seconds_after=0),
        make_event("PAYMENT_FAILED", transaction_id=None, seconds_after=10),
        make_event("FRAUD_CHECK", transaction_id=None, seconds_after=20),
        make_event("PAYMENT_SUCCESS", transaction_id=None, seconds_after=30),
    ]

    assert rule.evaluate(events) == []


def test_ignores_unrelated_event_types():
    rule = PaymentFraudRule()

    events = [
        make_event("LOGIN_FAILED", seconds_after=0),
        make_event("LOGIN_FAILED", seconds_after=10),
        make_event("FRAUD_CHECK", seconds_after=20),
        make_event("PAYMENT_SUCCESS", seconds_after=30),
    ]

    assert rule.evaluate(events) == []


def test_detects_events_at_window_boundary():
    rule = PaymentFraudRule(window_seconds=60)

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0, event_id="E1"),
        make_event("PAYMENT_FAILED", seconds_after=1, event_id="E2"),
        make_event("FRAUD_CHECK", seconds_after=2, event_id="E3"),
        make_event("PAYMENT_SUCCESS", seconds_after=60, event_id="E4"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == ["E1", "E2", "E3", "E4"]


def test_does_not_alert_when_failures_fall_outside_window():
    rule = PaymentFraudRule(window_seconds=60)

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0),
        make_event("PAYMENT_FAILED", seconds_after=1),
        make_event("FRAUD_CHECK", seconds_after=2),
        make_event("PAYMENT_SUCCESS", seconds_after=62),
    ]

    assert rule.evaluate(events) == []


def test_returns_at_most_one_alert_per_transaction():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0),
        make_event("PAYMENT_FAILED", seconds_after=10),
        make_event("FRAUD_CHECK", seconds_after=20),
        make_event("PAYMENT_SUCCESS", seconds_after=30),
        make_event("PAYMENT_SUCCESS", seconds_after=40, event_id="E5"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1


def test_includes_unique_sorted_source_ips():
    rule = PaymentFraudRule()

    events = [
        make_event("PAYMENT_FAILED", seconds_after=0, ip_address="192.168.1.21"),
        make_event("PAYMENT_FAILED", seconds_after=10, ip_address="192.168.1.20"),
        make_event("FRAUD_CHECK", seconds_after=20, ip_address="192.168.1.21"),
        make_event("PAYMENT_SUCCESS", seconds_after=30, ip_address=None),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].metadata["source_ips"] == [
        "192.168.1.20",
        "192.168.1.21",
    ]


@pytest.mark.parametrize("window_seconds", [0, -1])
def test_rejects_invalid_window(window_seconds):
    with pytest.raises(
        ValueError,
        match="window_seconds must be at least 1",
    ):
        PaymentFraudRule(window_seconds=window_seconds)