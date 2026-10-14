from datetime import datetime, timedelta, timezone

from opslens.detection.rules.rapid_transactions_rule import RapidTransactionsRule
from opslens.models.security_event import SecurityEvent


BASE_TIME = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_type="PAYMENT_SUCCESS",
    user_id="U102",
    transaction_id="TX1",
    seconds_after=0,
    event_id=None,
):
    event = SecurityEvent(
        service="payment-service",
        event_type=event_type,
        user_id=user_id,
        transaction_id=transaction_id,
        timestamp=BASE_TIME + timedelta(seconds=seconds_after),
    )

    if event_id is not None:
        event.event_id = event_id

    return event


def test_detects_transactions_at_limit():
    rule = RapidTransactionsRule(
        transaction_limit=5,
        time_window_seconds=60,
    )

    events = [
        make_event(seconds_after=seconds, transaction_id=f"TX{i}", event_id=f"E{i}")
        for i, seconds in enumerate([0, 10, 20, 30, 40], start=1)
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].rule == "RAPID_TRANSACTION_DETECTION"
    assert alerts[0].severity == "HIGH"
    assert alerts[0].user_id == "U102"
    assert alerts[0].metadata["transaction_count"] == 5
    assert alerts[0].metadata["transaction_limit"] == 5
    assert alerts[0].metadata["time_window_seconds"] == 60
    assert alerts[0].metadata["transaction_ids"] == [
        "TX1", "TX2", "TX3", "TX4", "TX5"
    ]


def test_does_not_alert_below_transaction_limit():
    rule = RapidTransactionsRule(transaction_limit=5)

    events = [
        make_event(seconds_after=seconds)
        for seconds in [0, 10, 20, 30]
    ]

    assert rule.evaluate(events) == []


def test_does_not_count_failed_payments():
    rule = RapidTransactionsRule(transaction_limit=3)

    events = [
        make_event(event_type="PAYMENT_FAILED", seconds_after=seconds)
        for seconds in [0, 10, 20, 30]
    ]

    assert rule.evaluate(events) == []


def test_groups_transactions_by_user():
    rule = RapidTransactionsRule(transaction_limit=3)

    events = [
        make_event(user_id="U102", seconds_after=0),
        make_event(user_id="U102", seconds_after=10),
        make_event(user_id="U103", seconds_after=20),
        make_event(user_id="U103", seconds_after=30),
    ]

    assert rule.evaluate(events) == []


def test_detects_users_independently():
    rule = RapidTransactionsRule(transaction_limit=3)

    events = [
        make_event(user_id="U102", seconds_after=0, transaction_id="A1"),
        make_event(user_id="U103", seconds_after=1, transaction_id="B1"),
        make_event(user_id="U102", seconds_after=2, transaction_id="A2"),
        make_event(user_id="U103", seconds_after=3, transaction_id="B2"),
        make_event(user_id="U102", seconds_after=4, transaction_id="A3"),
        make_event(user_id="U103", seconds_after=5, transaction_id="B3"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 2
    assert {alert.user_id for alert in alerts} == {"U102", "U103"}


def test_sorts_events_chronologically():
    rule = RapidTransactionsRule(transaction_limit=3)

    events = [
        make_event(seconds_after=20, transaction_id="TX3", event_id="E3"),
        make_event(seconds_after=0, transaction_id="TX1", event_id="E1"),
        make_event(seconds_after=10, transaction_id="TX2", event_id="E2"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].event_ids == ["E1", "E2", "E3"]


def test_includes_transaction_exactly_at_window_boundary():
    rule = RapidTransactionsRule(
        transaction_limit=3,
        time_window_seconds=60,
    )

    events = [
        make_event(seconds_after=0, event_id="E1"),
        make_event(seconds_after=30, event_id="E2"),
        make_event(seconds_after=60, event_id="E3"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].metadata["transaction_count"] == 3


def test_does_not_alert_when_transactions_exceed_window():
    rule = RapidTransactionsRule(
        transaction_limit=3,
        time_window_seconds=60,
    )

    events = [
        make_event(seconds_after=0),
        make_event(seconds_after=30),
        make_event(seconds_after=61),
    ]

    assert rule.evaluate(events) == []


def test_ignores_events_without_user_id():
    rule = RapidTransactionsRule(transaction_limit=3)

    events = [
        make_event(user_id=None, seconds_after=0),
        make_event(user_id=None, seconds_after=10),
        make_event(user_id=None, seconds_after=20),
    ]

    assert rule.evaluate(events) == []


def test_includes_only_nonempty_transaction_ids():
    rule = RapidTransactionsRule(transaction_limit=3)

    events = [
        make_event(transaction_id="TX1", seconds_after=0),
        make_event(transaction_id=None, seconds_after=10),
        make_event(transaction_id="TX3", seconds_after=20),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
    assert alerts[0].metadata["transaction_ids"] == ["TX1", "TX3"]


def test_returns_at_most_one_alert_per_user():
    rule = RapidTransactionsRule(transaction_limit=3)

    events = [
        make_event(seconds_after=0, transaction_id="TX1"),
        make_event(seconds_after=5, transaction_id="TX2"),
        make_event(seconds_after=10, transaction_id="TX3"),
        make_event(seconds_after=15, transaction_id="TX4"),
        make_event(seconds_after=20, transaction_id="TX5"),
    ]

    alerts = rule.evaluate(events)

    assert len(alerts) == 1
