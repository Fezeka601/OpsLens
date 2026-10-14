import pytest

from opslens.detection.anomaly_detector import DetectionEngine
from opslens.models.security_alert import SecurityAlert


class FakeRule:
    def __init__(self, result):
        self.result = result
        self.received_events = None

    def evaluate(self, events):
        self.received_events = events
        return self.result


def test_detect_returns_empty_list_when_no_rules_exist():
    engine = DetectionEngine(rules=[])

    result = engine.detect(events=[])

    assert result == []


def test_detect_returns_alerts_from_a_rule():
    alert = SecurityAlert(
        rule="TEST_RULE",
        severity="HIGH",
        message="Test alert",
        user_id="U102",
    )
    rule = FakeRule([alert])
    events = []

    engine = DetectionEngine(rules=[rule])
    result = engine.detect(events)

    assert result == [alert]
    assert rule.received_events is events


def test_detect_combines_alerts_from_multiple_rules():
    alert_one = SecurityAlert(
        rule="RULE_ONE",
        severity="HIGH",
        message="First test alert",
        user_id="U102",
    )
    alert_two = SecurityAlert(
        rule="RULE_TWO",
        severity="MEDIUM",
        message="Second test alert",
        user_id="U103",
    )

    engine = DetectionEngine(
        rules=[
            FakeRule([alert_one]),
            FakeRule([alert_two]),
        ]
    )

    result = engine.detect(events=[])

    assert result == [alert_one, alert_two]


def test_detect_raises_type_error_when_rule_returns_none():
    engine = DetectionEngine(
        rules=[FakeRule(None)]
    )

    with pytest.raises(
        TypeError,
        match=r"returned None; expected a list",
    ):
        engine.detect(events=[])


@pytest.mark.parametrize(
    "invalid_result",
    [
        "not a list",
        {"alert": "invalid"},
        123,
        (),
    ],
)
def test_detect_raises_type_error_when_rule_returns_wrong_type(
    invalid_result,
):
    engine = DetectionEngine(
        rules=[FakeRule(invalid_result)]
    )

    with pytest.raises(
        TypeError,
        match="expected a list of SecurityAlert objects",
    ):
        engine.detect(events=[])


def test_detect_preserves_alert_order():
    first = SecurityAlert(
        rule="FIRST",
        severity="LOW",
        message="First alert",
        user_id="U101",
    )
    second = SecurityAlert(
        rule="SECOND",
        severity="HIGH",
        message="Second alert",
        user_id="U102",
    )

    engine = DetectionEngine(
        rules=[
            FakeRule([first]),
            FakeRule([second]),
        ]
    )

    result = engine.detect(events=[])

    assert result[0] is first
    assert result[1] is second