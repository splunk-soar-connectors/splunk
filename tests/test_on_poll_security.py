# Copyright (c) 2016-2026 Splunk Inc.

from src.actions.on_poll import _get_splunk_severity


def test_enterprise_security_urgency_takes_precedence_over_event_severity():
    item = {"urgency": "critical", "severity": "informational"}

    assert _get_splunk_severity(item) == "high"


def test_event_severity_is_used_when_urgency_is_unmapped():
    item = {"urgency": "unknown", "severity": ["Low", "High"]}

    assert _get_splunk_severity(item) == "high"
