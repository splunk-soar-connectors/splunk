# Copyright (c) 2016-2026 Splunk Inc.

from pathlib import Path


def test_run_query_context_menu_escapes_host_for_javascript():
    template = Path("templates/splunk_run_query.html").read_text()

    assert '"value": {{ v|tojson }}' in template
    assert "escapejs" not in template
    assert '"value": {{ v }}' not in template
