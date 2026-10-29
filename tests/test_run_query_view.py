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

from src.actions.run_query import display_view


def test_display_view_starts_with_widget_root_and_contains_results_table():
    result = ActionResult(status=True, message="ok")
    result.set_summary(
        {
            "query": "index=main",
            "display": "host,count",
            "parse_only": False,
            "search_mode": "smart",
        }
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

    rendered = display_view("run_query", app_runs, context)
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
    context = {"container": 123}
    app_runs = [({"total_objects": 1}, [result]) for result in results]
    return BeautifulSoup(display_view("run_query", app_runs, context), "html.parser")


def test_display_view_uses_each_results_summary_and_display_fields():
    first = ActionResult(True, "ok", {"query": "stale", "display": "count"})
    first.set_summary({"query": "index=one", "display": "host"})
    first.add_data(
        {"host": "server-1", "count": 3, "_param_query": "stale event metadata"}
    )
    second = ActionResult(True, "ok")
    second.set_summary({"query": "index=two", "display": "count"})
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


def test_display_view_falls_back_to_saved_parameters_for_historical_results():
    result = ActionResult(True, "ok", {"query": "index=historical", "display": "count"})
    result.set_summary({"sid": "old-search-id", "total_events": 1})
    result.add_data({"host": "server-1", "count": 3})

    document = _render_results(result)

    assert document.select_one(".datatable").get_text(" ", strip=True) == "count 3"
    info = document.select_one(".wf-table-vertical").get_text(" ", strip=True)
    assert "Query index=historical" in info
    assert "Parse Only False" in info
    assert "Search Mode smart" in info


@pytest.mark.parametrize(
    ("display", "expected"),
    [("", "host server-1"), ("_raw,host", "_raw host raw event server-1")],
)
def test_display_view_hides_system_fields_unless_explicitly_selected(display, expected):
    result = ActionResult(True, "ok")
    result.set_summary({"display": display})
    event = {"_raw": "raw event", "host": "server-1"}
    result.add_data(event)

    document = _render_results(result)

    assert document.select_one(".datatable").get_text(" ", strip=True) == expected
    assert result.get_data() == [event]


def test_display_view_handles_an_empty_query_result_alongside_nonempty_results():
    empty = ActionResult(True, "ok")
    empty.set_summary({"query": "index=empty", "total_events": 0})
    nonempty = ActionResult(True, "ok")
    nonempty.set_summary({"query": "index=main"})
    nonempty.add_data({"count": 1})

    document = _render_results(empty, nonempty)

    assert "No data found" in document.get_text()
    assert document.select_one(".datatable").get_text(" ", strip=True) == "count 1"


def test_display_view_handles_no_action_results():
    document = _render_results()

    assert "No data found" in document.get_text()


def test_display_view_escapes_summary_values_as_html():
    result = ActionResult(True, "ok")
    query = '<script>alert("query")</script>'
    result.set_summary({"query": query})
    result.add_data({"count": 1})

    document = _render_results(result)
    info = document.select_one(".wf-table-vertical")

    assert query in info.get_text()
    assert info.select_one("script") is None
