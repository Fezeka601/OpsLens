from datetime import datetime, timezone

import pytest

from opslens.detection.rules.unusual_payment_amount_rule import (
    UnusualPaymentAmountRule,
)
from opslens.models.security_event import SecurityEvent


BASE_TIME = datetime(
    2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc
)


def make_event(
    event_type="PAYMENT_SUCCESS",
    user_id="U101",
    amount=75000,
    currency="ZAR",
    transaction_id="TX1001",
    ip_address="192.168.1.10",
    event_id=None,
):
    metadata = {}

    if amount is not ...:
        metadata["amount"] = amount

    if currency is not ...:
        metadata["currency"] = currency

    event = SecurityEvent(
        service="payment-service",
        event_type=event_type,
        user_id=user_id,
        transaction_id=transaction_id,
        timestamp=BASE_TIME,
        ip_address=ip_address,
        metadata=metadata,
    )

    if event_id is not None:
        event.event_id = event_id

    return event


def test_detects_payment_above_default_threshold():
    rule = UnusualPaymentAmountRule()

    alerts = rule.evaluate([
        make_event(amount=75000, event_id="E1"),
    ])

    assert len(alerts) == 1
    assert alerts[0].rule == "UNUSUAL_PAYMENT_AMOUNT"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].user_id == "U101"
    assert alerts[0].event_ids == ["E1"]


def test_detects_payment_exactly_at_threshold():
    rule = UnusualPaymentAmountRule(threshold=50000)

    alerts = rule.evaluate([
        make_event(amount=50000),
    ])

    assert len(alerts) == 1
    assert alerts[0].metadata["amount"] == 50000.0


def test_does_not_alert_below_threshold():
    rule = UnusualPaymentAmountRule(threshold=50000)

    alerts = rule.evaluate([
        make_event(amount=49999.99),
    ])

    assert alerts == []


def test_supports_custom_threshold():
    rule = UnusualPaymentAmountRule(threshold=10000)

    alerts = rule.evaluate([
        make_event(amount=10000),
        make_event(amount=9999),
    ])

    assert len(alerts) == 1
    assert alerts[0].metadata["amount"] == 10000.0


def test_ignores_non_successful_payment_events():
    rule = UnusualPaymentAmountRule()

    events = [
        make_event(event_type="PAYMENT_FAILED", amount=90000),
        make_event(event_type="FRAUD_CHECK", amount=90000),
    ]

    assert rule.evaluate(events) == []


@pytest.mark.parametrize(
    "amount",
    [
        None,
        True,
        False,
        "not-a-number",
        "",
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_ignores_invalid_or_non_finite_amounts(amount):
    rule = UnusualPaymentAmountRule()

    alerts = rule.evaluate([
        make_event(amount=amount),
    ])

    assert alerts == []


def test_ignores_missing_amount():
    rule = UnusualPaymentAmountRule()

    alerts = rule.evaluate([
        make_event(amount=...),
    ])

    assert alerts == []


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        (75000, 75000.0),
        (75000.50, 75000.50),
        ("75000", 75000.0),
        ("75000.50", 75000.50),
    ],
)
def test_accepts_numeric_values_and_numeric_strings(amount, expected):
    rule = UnusualPaymentAmountRule()

    alerts = rule.evaluate([
        make_event(amount=amount),
    ])

    assert len(alerts) == 1
    assert alerts[0].metadata["amount"] == expected


def test_alert_metadata_contains_payment_details():
    rule = UnusualPaymentAmountRule(threshold=50000)

    alerts = rule.evaluate([
        make_event(
            amount="75000.50",
            currency="ZAR",
            transaction_id="TX9003",
            ip_address="192.168.1.21",
        ),
    ])

    assert len(alerts) == 1

    metadata = alerts[0].metadata

    assert metadata["amount"] == 75000.50
    assert metadata["currency"] == "ZAR"
    assert metadata["threshold"] == 50000
    assert metadata["transaction_id"] == "TX9003"
    assert metadata["ip_address"] == "192.168.1.21"


def test_handles_missing_currency():
    rule = UnusualPaymentAmountRule()

    alerts = rule.evaluate([
        make_event(currency=...),
    ])

    assert len(alerts) == 1
    assert alerts[0].metadata["currency"] is None
    assert "ZAR" not in alerts[0].message


def test_evaluates_each_payment_independently():
    rule = UnusualPaymentAmountRule()

    events = [
        make_event(
            amount=75000,
            transaction_id="TX1001",
            event_id="E1",
        ),
        make_event(
            amount=20000,
            transaction_id="TX1002",
            event_id="E2",
        ),
        make_event(
            amount=90000,
            transaction_id="TX1003",
            event_id="E3",
        ),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert [alert.event_ids for alert in alerts] == [["E1"], ["E3"]]
