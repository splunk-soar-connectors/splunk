# Copyright (c) 2016-2026 Splunk Inc.

from bs4.dammit import UnicodeDammit
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, SplunkHelper, app
from ..splunk_consts import SPLUNK_DEFAULT_SOURCE, SPLUNK_DEFAULT_SOURCE_TYPE

logger = getLogger()


class PostDataParams(Params):
    data: str = Param(description="Data to post", required=True)
    host: str = Param(
        description="Host for event",
        required=False,
        default="",
        primary=True,
        cef_types=["ip", "host name"],
    )
    index: str = Param(description="Index to send event to", required=False, default="")
    source: str = Param(description="Source for event", required=False, default="Phantom")
    source_type: str = Param(
        description="Type of source for event",
        required=False,
        default="Automation/Orchestration Platform",
    )


class PostDataOutput(ActionOutput):
    status: str | None = OutputField(column_name="Status")
    message: str | None = OutputField(column_name="Message")


@app.action(
    description="Post data to Splunk",
    action_type="generic",
    read_only=False,
    render_as="table",
)
def post_data(params: PostDataParams, soar: SOARClient, asset: Asset) -> list[PostDataOutput]:
    helper = SplunkHelper(asset)
    helper.validate_asset()

    try:
        post_bytes = UnicodeDammit(params.data).unicode_markup.encode("utf-8")
    except Exception as e:
        logger.error("Error while encoding data: %s", e)
        post_bytes = params.data.encode("utf-8")

    get_params: dict[str, str] = {
        "source": params.source or SPLUNK_DEFAULT_SOURCE,
        "sourcetype": params.source_type or SPLUNK_DEFAULT_SOURCE_TYPE,
    }
    if params.host:
        get_params["host"] = params.host
    if params.index:
        get_params["index"] = params.index

    helper.make_rest_call_retry("receivers/simple", post_bytes, params=get_params)

    soar.set_message("Successfully posted the data")
    return [PostDataOutput(status="success", message="Successfully posted the data")]
