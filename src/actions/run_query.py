# Copyright (c) 2016-2026 Splunk Inc.

import json

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, PermissiveActionOutput
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, SplunkHelper, app
from ..splunk_consts import SPLUNK_SEARCH_MODE_SMART

logger = getLogger()


class RunQueryParams(Params):
    command: str = Param(
        description="Beginning command (in Splunk Processing Language)",
        required=False,
        value_list=["search", "eval", "savedsearch", "stats", "table", "tstats"],
        default="search",
    )
    query: str = Param(
        description="Query to run (in Splunk Processing Language)",
        required=True,
        primary=True,
        cef_types=["splunk query"],
    )
    display: str = Param(description="Display fields (comma-separated)", required=False, default="")
    parse_only: bool = Param(description="Parse only", required=False, default=False)
    add_raw_field: bool = Param(description="Ingest _raw field data", required=False, default=True)
    attach_result: bool = Param(description="Attach result to the vault", required=False, default=False)
    start_time: str = Param(description="Earliest time modifier", required=False, default="")
    end_time: str = Param(description="Latest time modifier", required=False, default="")
    search_mode: str = Param(
        description="Search mode",
        required=False,
        value_list=["fast", "verbose", "smart"],
        default="smart",
    )
    time_format: str = Param(description="Custom timestamp format", required=False, default="")


class RunQueryOutput(PermissiveActionOutput):
    pass


class RunQuerySummary(ActionOutput):
    sid: str | None = None
    total_events: int | None = None


@app.view_handler(template="splunk_run_query.html")
def display_view(outputs: list[RunQueryOutput]) -> dict:
    if not outputs:
        return {"results": [{"data": {}, "param": {}}]}

    first = outputs[0].model_dump(exclude_none=True)
    param = {
        "query": first.get("_param_query", ""),
        "command": first.get("_param_command", ""),
        "display": first.get("_param_display", ""),
        "parse_only": first.get("_param_parse_only", False),
        "search_mode": first.get("_param_search_mode", "smart"),
    }
    display_fields = param.get("display", "")

    all_data = []
    for output in outputs:
        data = {k: v for k, v in output.model_dump(exclude_none=True).items() if not k.startswith("_")}
        all_data.append(data)

    if display_fields:
        headers = [x.strip() for x in display_fields.split(",") if x.strip()]
    elif all_data:
        headers = [k for k in all_data[0] if not k.startswith("_")]
    else:
        headers = []

    processed_data = [{h: item.get(h) for h in headers} for item in all_data]

    return {
        "results": [{
            "param": param,
            "data": all_data or {},
            "processed_data": processed_data,
            "headers": headers,
        }],
    }


@app.action(
    description="Run a search query on the Splunk device. Please escape any quotes that are part of the query string",
    action_type="investigate",
    read_only=True,
    view_handler=display_view,
    summary_type=RunQuerySummary,
)
def run_query(params: RunQueryParams, soar: SOARClient, asset: Asset) -> list[RunQueryOutput]:
    helper = SplunkHelper(asset)
    helper.validate_asset()
    helper.connect()

    search_mode = params.search_mode or SPLUNK_SEARCH_MODE_SMART
    kwargs: dict = {"adhoc_search_level": search_mode}
    if params.start_time:
        kwargs["earliest_time"] = params.start_time
    if params.end_time:
        kwargs["latest_time"] = params.end_time
    if params.time_format:
        kwargs["time_format"] = params.time_format

    search_command = params.command
    search_string = params.query

    if not search_command:
        if search_string[0] != "|" and not search_string.startswith("search"):
            search_string = f"search {search_string.strip()}"
        search_query = search_string
    else:
        search_query = f"{search_command.strip()} {search_string.strip()}"

    sid, results_list = helper.run_query(
        search_query,
        kwargs_create=kwargs,
        parse_only=params.parse_only,
        add_raw_field=params.add_raw_field,
    )

    if params.attach_result:
        _attach_json_result(soar, results_list)

    soar.set_summary(RunQuerySummary(sid=sid, total_events=len(results_list)))
    soar.set_message(f"Sid: {sid}, Total events: {len(results_list)}")

    param_info = {
        "_param_query": params.query,
        "_param_command": params.command,
        "_param_display": params.display,
        "_param_parse_only": params.parse_only,
        "_param_search_mode": search_mode,
    }
    return [RunQueryOutput(**{**r, **param_info}) for r in results_list]


def _attach_json_result(soar: SOARClient, data: list[dict]):
    try:
        container_id = soar.get_executing_container_id()
        soar.vault.create_attachment(
            container_id=container_id,
            file_content=json.dumps(data),
            file_name="splunk_run_query_result.json",
        )
    except Exception as e:
        logger.error("Error attaching results to vault: %s", e)
