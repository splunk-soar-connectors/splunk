# Copyright (c) 2016-2026 Splunk Inc.

import json
import re

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.logging import getLogger
from soar_sdk.params import Param, Params

from ..app import Asset, SplunkHelper, app
from ..splunk_consts import (
    SPLUNK_DISPOSITION_QUERY_FORMAT,
    SPLUNK_ERR_BAD_DISPOSITION,
    SPLUNK_ERR_BAD_STATUS,
    SPLUNK_ERR_NEED_PARAM,
    SPLUNK_ERR_NOT_ES,
)

logger = getLogger()


class UpdateEventParams(Params):
    event_ids: str = Param(
        description="Event ID to update",
        required=True,
        primary=True,
        cef_types=["splunk notable event id"],
    )
    owner: str = Param(
        description="New owner for the event", required=False, default=""
    )
    status: str = Param(
        description="New status for the event",
        required=False,
        default="",
        value_list=[
            "",
            "unassigned",
            "new",
            "in progress",
            "pending",
            "resolved",
            "closed",
        ],
    )
    integer_status: str = Param(
        description="Integer representing custom status value",
        required=False,
        default="",
    )
    urgency: str = Param(
        description="New urgency for the event",
        required=False,
        default="",
        value_list=["", "informational", "low", "medium", "high", "critical"],
    )
    comment: str = Param(
        description="New comment for the event", required=False, default=""
    )
    disposition: str = Param(
        description="New disposition field",
        required=False,
        default="",
        value_list=[
            "",
            "Unassigned",
            "True Positive - Suspicious Activity",
            "Benign Positive - Suspicious But Expected",
            "False Positive - Incorrect Analytic Logic",
            "False Positive - Inaccurate Data",
            "Undetermined",
            "Other",
        ],
    )
    integer_disposition: str = Param(
        description="Integer representing custom disposition value",
        required=False,
        default="",
    )
    wait_for_confirmation: bool = Param(
        description="Validate event_ids", required=False, default=False
    )


class UpdateEventOutput(ActionOutput):
    status: str | None = OutputField(column_name="Status")
    failure_count: int | None = None
    message: str | None = OutputField(column_name="Message")
    success: bool | None = None
    success_count: int | None = None


class UpdateEventSummary(ActionOutput):
    sid: str | None = None
    updated_event_id: str | None = None


@app.action(
    description="Update a notable event",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateEventSummary,
)
def update_event(
    params: UpdateEventParams, soar: SOARClient, asset: Asset
) -> list[UpdateEventOutput]:
    helper = SplunkHelper(asset)
    helper.validate_asset()

    if not helper.check_for_es():
        raise RuntimeError(SPLUNK_ERR_NOT_ES)

    ids = params.event_ids
    owner = params.owner
    status = params.status
    comment = params.comment
    urgency = params.urgency
    disposition = params.disposition or ""
    wait_for_confirmation = params.wait_for_confirmation

    integer_status = SplunkHelper.validate_integer(
        params.integer_status, "'integer_status' action", allow_zero=True
    )
    integer_disposition = SplunkHelper.validate_integer(
        params.integer_disposition, "'integer_disposition' action", allow_zero=True
    )

    if (
        not any([comment, status, urgency, owner, disposition])
        and integer_status is None
        and integer_disposition is None
    ):
        raise ValueError(SPLUNK_ERR_NEED_PARAM)

    splunk_status_dict: dict[str, int] = {}
    splunk_disposition_dict: dict[str, int] = {}

    if status or integer_status is not None:
        splunk_status_dict = helper.get_status_dict("notable")
        if not splunk_status_dict:
            raise RuntimeError("Error occurred while fetching Splunk event status")

    if disposition or integer_disposition is not None:
        splunk_disposition_dict = helper.get_status_dict("disposition")
        if not splunk_disposition_dict:
            raise RuntimeError("Error occurred while fetching Splunk event disposition")

    helper.connect()

    # Resolve SID+RID combo to event_id
    regexp = re.compile(r"\+\d*(\.\d+)?[\"$]")
    if regexp.search(json.dumps(ids)):
        logger.progress("Interpreting the event ID as an SID + RID combo")
        try:
            ids = helper.resolve_event_id(ids)
        except Exception:
            raise RuntimeError(
                "Unable to find underlying event_id from SID + RID combo"
            ) from None

    if wait_for_confirmation:
        search_query = f"search `notable_by_id({ids})`"
        _sid, validate_results = helper.run_query(search_query)
        if not validate_results:
            raise ValueError("Please provide a valid event ID")

    request_body: dict = {"ruleUIDs": ids}

    # Status
    if integer_status is not None:
        if int(integer_status) not in list(splunk_status_dict.values()):
            raise ValueError(
                "Please provide a valid value in 'integer_status' action parameter. "
                f"Valid values: {', '.join(map(str, splunk_status_dict.values()))}"
            )
        request_body["status"] = str(integer_status)
    elif status:
        if status not in splunk_status_dict:
            if not status.isdigit():
                raise ValueError(SPLUNK_ERR_BAD_STATUS)
            request_body["status"] = status
        else:
            request_body["status"] = splunk_status_dict[status]

    # Disposition
    if integer_disposition is not None:
        if int(integer_disposition) not in splunk_disposition_dict.values():
            raise ValueError(
                "Please provide a valid value in 'integer_disposition' action parameter. "
                f"Valid values: {', '.join(map(str, splunk_disposition_dict.values()))}"
            )
        request_body["disposition"] = SPLUNK_DISPOSITION_QUERY_FORMAT.format(
            integer_disposition
        )
    elif disposition:
        if disposition not in splunk_disposition_dict:
            if not disposition.isdigit():
                raise ValueError(SPLUNK_ERR_BAD_DISPOSITION)
            request_body["disposition"] = SPLUNK_DISPOSITION_QUERY_FORMAT.format(
                disposition
            )
        else:
            request_body["disposition"] = SPLUNK_DISPOSITION_QUERY_FORMAT.format(
                splunk_disposition_dict[disposition]
            )

    param_mapping = {"urgency": urgency, "comment": comment, "newOwner": owner}
    request_body.update({k: v for k, v in param_mapping.items() if v})

    resp_data = helper.make_rest_call_retry("notable_update", request_body)

    if resp_data and "success" in resp_data and not resp_data.get("success"):
        msg = resp_data.get("message")
        raise RuntimeError(msg if msg else "Unable to update the notable event")

    soar.set_summary(UpdateEventSummary(updated_event_id=ids))

    if wait_for_confirmation:
        msg = f"Updated Event ID: {ids}"
    else:
        msg = (
            f"Updated Event ID: {ids}. The event_id has not been verified. "
            "Please confirm that the provided event_id corresponds to an actual notable event"
        )

    soar.set_message(msg)

    if resp_data:
        resp_data["status"] = "success"
        resp_data["message"] = msg
        return [UpdateEventOutput(**resp_data)]
    return [UpdateEventOutput(status="success", message=msg)]
