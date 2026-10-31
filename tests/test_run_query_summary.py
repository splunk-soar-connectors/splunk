# Copyright (c) 2026 Splunk Inc.

import importlib
import json
from unittest.mock import Mock

import pytest

from src.actions.run_query import RunQueryParams, run_query
from src.app import Asset, app

run_query_module = importlib.import_module("src.actions.run_query")


@pytest.mark.parametrize(
    "events", [[], [{"host": "server-1", "_raw": "event"}, {"count": 2}]]
)
@pytest.mark.parametrize("search_mode", ["verbose", ""])
@pytest.mark.parametrize("parse_only", [False, True])
def test_run_query_preserves_separate_events_parameters_and_summary(
    monkeypatch, events, search_mode, parse_only
):
    helper = Mock()
    helper.run_query.return_value = ("search-id", events)
    monkeypatch.setattr(run_query_module, "SplunkHelper", Mock(return_value=helper))
    add_result = Mock()
    monkeypatch.setattr(app.actions_manager, "add_result", add_result)
    soar = Mock()
    soar.get_summary.side_effect = lambda: soar.set_summary.call_args.args[0]
    soar.get_message.side_effect = lambda: soar.set_message.call_args.args[0]
    params = RunQueryParams(
        query="index=main",
        command="search",
        display="host,count",
        parse_only=parse_only,
        search_mode=search_mode,
        attach_result=True,
    )

    assert run_query(params, soar=soar, asset=Asset(device="splunk.example.com"))

    result = add_result.call_args.args[0]
    assert result.get_data() == events
    assert result.get_summary() == {
        "sid": "search-id",
        "total_events": len(events),
    }
    assert result.get_param() == params.model_dump()
    assert helper.run_query.call_args.kwargs["kwargs_create"]["adhoc_search_level"] == (
        search_mode or "smart"
    )
    assert result.get_message() == f"Sid: search-id, Total events: {len(events)}"
    assert (
        json.loads(soar.vault.create_attachment.call_args.kwargs["file_content"])
        == events
    )
