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
from soar_sdk.action_results import ActionResult

from src.actions.run_query import display_view


def test_display_view_starts_with_widget_root_and_contains_results_table():
    result = ActionResult(status=True, message="ok")
    result.add_data(
        {
            "host": "server-1",
            "count": "3",
            "_param_query": "index=main",
            "_param_display": "host,count",
            "_param_parse_only": False,
            "_param_search_mode": "smart",
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
