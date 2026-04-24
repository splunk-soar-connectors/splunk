# Copyright (c) 2016-2026 Splunk Inc.

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.params import Param, Params

from ..app import Asset, SplunkHelper, app


class GetHostEventsParams(Params):
    ip_hostname: str = Param(
        description="Hostname/IP to search the events of",
        required=True,
        primary=True,
        cef_types=["ip", "host name"],
    )
    last_n_days: str = Param(description="Number of days ago", required=False, default="")


class GetHostEventsOutput(PermissiveActionOutput):
    host: str | None = OutputField(column_name="Host")
    time: str | None = OutputField(column_name="Time", alias="_time")
    raw: str | None = OutputField(column_name="Raw", alias="_raw")


class GetHostEventsSummary(ActionOutput):
    sid: str | None = None
    total_events: int | None = None


@app.action(
    description="Get events pertaining to a host that have occurred in the last 'N' days",
    action_type="investigate",
    read_only=True,
    render_as="table",
    summary_type=GetHostEventsSummary,
)
def get_host_events(params: GetHostEventsParams, soar: SOARClient, asset: Asset) -> list[GetHostEventsOutput]:
    helper = SplunkHelper(asset)
    helper.validate_asset()
    helper.connect()

    ip_hostname = params.ip_hostname
    last_n_days = SplunkHelper.validate_integer(params.last_n_days, "'last_n_days' action")

    search_query = f'search host="{ip_hostname}"'
    if last_n_days:
        search_query += f" earliest=-{last_n_days}d"

    sid, results_list = helper.run_query(search_query)

    soar.set_summary(GetHostEventsSummary(sid=sid, total_events=len(results_list)))
    soar.set_message(f"Sid: {sid}, Total events: {len(results_list)}")

    return [GetHostEventsOutput(**r) for r in results_list]
