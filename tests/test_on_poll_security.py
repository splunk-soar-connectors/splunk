# Copyright (c) 2016-2026 Splunk Inc.

from src.actions.on_poll import _get_splunk_severity, _sanitize_ingested_value


def test_enterprise_security_urgency_takes_precedence_over_event_severity():
    item = {"urgency": "critical", "severity": "informational"}

    assert _get_splunk_severity(item) == "high"


def test_event_severity_is_used_when_urgency_is_unmapped():
    item = {"urgency": "unknown", "severity": ["Low", "High"]}

    assert _get_splunk_severity(item) == "high"


def test_ingested_strings_drop_nul_and_unicode_format_controls_recursively():
    value = {
        "file_name": "invoice\x00_\u200b_\u202efdp.scr",
        "nested": ["safe", {"user": "mal\u200dlory"}],
        "count": 2,
    }

    assert _sanitize_ingested_value(value) == {
        "file_name": "invoice__fdp.scr",
        "nested": ["safe", {"user": "mallory"}],
        "count": 2,
    }
