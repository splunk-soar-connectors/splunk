# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from bs4 import BeautifulSoup
from bs4.element import NavigableString, Tag
import pytest
from soar_sdk.action_results import ActionResult

from src.actions.run_query import RunQueryOutput, _get_context_result, display_view


def test_display_view_starts_with_widget_root_and_contains_results_table():
    result = ActionResult(
        True,
        "ok",
        {
            "query": "index=main",
            "display": "host,count",
            "parse_only": False,
            "search_mode": "smart",
        },
    )
    result.add_data(
        {
            "host": "server-1",
            "count": "3",
        }
    )
    context = {
        "accepts_prerender": True,
        "QS": {},
        "container": 123,
        "app": 456,
        "no_connection": False,
        "google_maps_key": False,
    }
    app_runs = [
        (
            {"total_objects": 1, "total_objects_successful": 1},
            [result],
        )
    ]

    # The SDK decorator supplies the handler's params and summary arguments.
    rendered = display_view("run_query", app_runs, context)  # pylint: disable=no-value-for-parameter
    document = BeautifulSoup(rendered, "html.parser")

    first_node = next(
        node
        for node in document.contents
        if not isinstance(node, NavigableString) or node.strip()
    )
    assert isinstance(first_node, Tag)
    table = document.select_one(".widget-body > .scoller .datatable")
    assert table is not None
    assert table.get_text(" ", strip=True) == "host count server-1 3"
    assert context["prerender"] is True
    assert "index=main" in document.select_one(".wf-table-vertical").get_text()


def _render_results(*results):
    context = {
        "QS": {},
        "container": 123,
        "app": 456,
        "no_connection": False,
        "google_maps_key": False,
    }
    app_runs = [
        ({"total_objects": 1, "total_objects_successful": 1}, [result])
        for result in results
    ]
    # The SDK decorator supplies the handler's params and summary arguments.
    rendered = display_view("run_query", app_runs, context)  # pylint: disable=no-value-for-parameter
    return BeautifulSoup(rendered, "html.parser")


def test_display_view_uses_each_results_parameters_and_display_fields():
    first = ActionResult(True, "ok", {"query": "index=one", "display": "host"})
    first.set_summary({"sid": "one-search", "total_events": 1})
    first.add_data(
        {"host": "server-1", "count": 3, "_param_query": "stale event metadata"}
    )
    second = ActionResult(True, "ok", {"query": "index=two", "display": "count"})
    second.set_summary({"sid": "two-search", "total_events": 1})
    second.add_data({"host": "server-2", "count": 7})

    document = _render_results(first, second)

    assert [
        table.get_text(" ", strip=True) for table in document.select(".datatable")
    ] == [
        "host server-1",
        "count 7",
    ]
    info = document.select(".wf-table-vertical")
    assert "index=one" in info[0].get_text()
    assert "index=two" in info[1].get_text()
    assert "stale" not in document.get_text()


def test_display_view_reads_saved_parameters_without_filling_in_defaults():
    result = ActionResult(
        True,
        "ok",
        {
            "query": "index=historical",
            "display": "count",
            "parse_only": True,
            "search_mode": "verbose",
        },
    )
    result.set_summary({"sid": "old-search-id", "total_events": 1})
    result.add_data({"host": "server-1", "count": 3})

    document = _render_results(result)

    assert document.select_one(".datatable").get_text(" ", strip=True) == "count 3"
    info = document.select_one(".wf-table-vertical").get_text(" ", strip=True)
    assert "Query index=historical" in info
    assert "Parse Only True" in info
    assert "Search Mode verbose" in info


def test_display_view_keeps_events_from_one_query_in_one_table():
    result = ActionResult(True, "ok", {"query": "index=main"})
    result.set_summary({"sid": "one-search", "total_events": 2})
    result.add_data({"host": "server-1", "count": 3})
    result.add_data({"host": "server-2", "count": 7})

    document = _render_results(result)

    tables = document.select(".datatable")
    assert len(tables) == 1
    assert tables[0].get_text(" ", strip=True) == "host count server-1 3 server-2 7"


@pytest.mark.parametrize(
    ("display", "expected"),
    [("", "host server-1"), ("_raw,host", "_raw host raw event server-1")],
)
def test_display_view_hides_system_fields_unless_explicitly_selected(display, expected):
    result = ActionResult(True, "ok", {"display": display})
    event = {"_raw": "raw event", "host": "server-1"}
    result.add_data(event)

    document = _render_results(result)

    assert document.select_one(".datatable").get_text(" ", strip=True) == expected
    assert result.get_data() == [event]


def test_display_view_handles_an_empty_query_result_alongside_nonempty_results():
    empty = ActionResult(True, "ok", {"query": "index=empty"})
    empty.set_summary({"sid": "empty-search", "total_events": 0})
    nonempty = ActionResult(True, "ok", {"query": "index=main"})
    nonempty.set_summary({"sid": "one-search", "total_events": 1})
    nonempty.add_data({"count": 1})

    document = _render_results(empty, nonempty)

    assert "No data found" not in document.get_text()
    assert document.select_one(".datatable").get_text(" ", strip=True) == "count 1"


def test_display_view_handles_no_action_results():
    document = _render_results()

    assert "No data found" in document.get_text()


def test_display_view_escapes_parameter_values_as_html():
    query = '<script>alert("query")</script>'
    result = ActionResult(True, "ok", {"query": query})
    result.add_data({"count": 1})

    document = _render_results(result)
    info = document.select_one(".wf-table-vertical")

    assert query in info.get_text()
    assert info.select_one("script") is None


def test_view_context_matches_legacy_structure_and_keeps_parameters_separate():
    params = {"query": "index=main", "display": "_raw, host, , missing"}
    # Even an older saved result with duplicated metadata must use its parameters.
    summary = {"sid": "one-search", "total_events": 2, "display": "count"}
    events = [
        {"host": "server-1", "_raw": "raw event", "count": 3},
        {"host": "server-2", "_raw": None, "count": 7},
    ]

    context = display_view.__wrapped__(
        None,
        "run query",
        [RunQueryOutput(**event) for event in events],
        [params, params],
        [summary, summary],
    )

    assert context == {
        "results": [
            {
                "param": params,
                "action_name": "run query",
                "summary": summary,
                "data": events,
                "headers": ["_raw", "host", "missing"],
                "processed_data": [
                    {"_raw": "raw event", "host": "server-1", "missing": None},
                    {"_raw": None, "host": "server-2", "missing": None},
                ],
            }
        ]
    }


@pytest.mark.parametrize("summary", [{}, {"sid": "empty-search", "total_events": 0}])
def test_empty_view_context_matches_legacy_structure(summary):
    params = {"query": "index=empty"}

    result = _get_context_result([], params, summary, "run query")

    expected = {"param": params, "action_name": "run query", "data": {}}
    if summary:
        expected["summary"] = summary
    assert result == expected


def test_display_view_keeps_queries_with_identical_parameters_separate():
    params = {"query": "index=main"}
    first = ActionResult(True, "ok", params)
    first.set_summary({"sid": "first-search", "total_events": 1})
    first.add_data({"count": 1})
    second = ActionResult(True, "ok", params)
    second.set_summary({"sid": "second-search", "total_events": 1})
    second.add_data({"count": 2})

    document = _render_results(first, second)

    assert [
        table.get_text(" ", strip=True) for table in document.select(".datatable")
    ] == [
        "count 1",
        "count 2",
    ]
