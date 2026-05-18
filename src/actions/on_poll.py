# Copyright (c) 2016-2026 Splunk Inc.

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC

from bs4.dammit import UnicodeDammit
from soar_sdk.abstract import SOARClient
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams

from ..app import Asset, SplunkHelper, app
from ..splunk_consts import CIM_CEF_MAP, SPLUNK_SEVERITY_MAP

logger = getLogger()


def _get_event_start(start_time: str | None) -> str | None:
    if not start_time:
        return None
    try:
        from dateutil.parser import ParserError, parse as dateutil_parse

        datetime_obj = dateutil_parse(start_time)
        return datetime_obj.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ParserError as e:
        logger.error("ParserError while parsing _time: %s", e)
        return None
    except Exception as e:
        logger.error("Exception while parsing _time: %s", e)
        return None


def _get_fips_enabled() -> bool:
    try:
        from phantom_common.install_info import is_fips_enabled

        return is_fips_enabled()
    except ImportError:
        return False


def _get_splunk_severity(item: dict) -> str:
    severity = item.get("severity")
    if isinstance(severity, list):
        for key in ["critical", "high", "medium", "low", "informational"]:
            if key in severity:
                return SPLUNK_SEVERITY_MAP[key]
        return ""
    severity = SPLUNK_SEVERITY_MAP.get(severity) if severity else None
    if not severity:
        urgency = item.get("urgency")
        severity = SPLUNK_SEVERITY_MAP.get(urgency, "medium")
    return severity


def _get_splunk_title(item: dict, prefix: str, name_values: list[str]) -> str:
    title = prefix
    values_list = list(name_values)
    if not title and not values_list:
        values_list.append("source")

    values = ""
    for i, nv in enumerate(values_list):
        if CIM_CEF_MAP.get(nv) and item.get(CIM_CEF_MAP.get(nv)):
            value = item.get(CIM_CEF_MAP.get(nv))
        elif item.get(nv):
            value = item.get(nv)
        else:
            value = CIM_CEF_MAP.get(nv, nv)
        values += f"{value}" + ("" if i == len(values_list) - 1 else ", ")

    if not title:
        t = item.get("_time")
        title = f"Splunk Log Entry on {t}" if t else "Splunk Log Entry"
    else:
        title = item.get(title, title)

    return f"{title}: {values}"


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    helper = SplunkHelper(asset)
    helper.validate_asset()
    helper.connect()

    search_command = asset.on_poll_command
    search_string = asset.on_poll_query
    po = asset.on_poll_parse_only
    include_cim_fields = asset.include_cim_fields
    use_event_id_sdi = asset.use_event_id_sdi

    if not search_string:
        raise ValueError("Need to specify Query String to use polling")

    try:
        if not search_command:
            if search_string[0] != "|" and not search_string.startswith("search"):
                search_string = f"search {search_string.strip()}"
            search_query = search_string
        else:
            search_query = f"{search_command.strip()} {search_string.strip()}"
    except Exception:
        raise ValueError("Error occurred while parsing the search query") from None

    search_params: dict = {}
    state = asset.ingest_state
    is_poll_now = params.is_manual_poll()

    if is_poll_now:
        search_params["max_count"] = params.container_count or 100
    else:
        search_params["max_count"] = asset.max_container
        start_time = state.get("start_time")
        if start_time:
            search_params["index_earliest"] = start_time

    if int(search_params["max_count"]) <= 0:
        logger.debug("container_count <= 0, ignoring max_count")
        search_params.pop("max_count")

    try:
        _sid, results_list = helper.run_query(
            search_query, kwargs_create=search_params, parse_only=po
        )
    except Exception as e:
        msg = str(e)
        if "Invalid index_earliest" in msg:
            logger.debug(
                "Invalid start_time %s, retrying without it",
                search_params.get("index_earliest"),
            )
            state.pop("start_time", None)
        raise

    display = asset.on_poll_display
    header_set = None
    if display:
        header_set = [x.strip().lower() for x in display.split(",")]

    data = list(reversed(results_list))
    logger.info("Total %d event(s) fetched", len(data))

    container_name_prefix = asset.container_name_prefix or ""
    raw_values = asset.container_name_values
    container_name_values = (
        [x.strip() for x in raw_values.split(",")] if raw_values else []
    )

    count = 1
    for item in data:
        try:
            cef: dict = {}
            if "_serial" in item:
                item.pop("_serial")

            if header_set:
                name_mappings = {k.lower(): k for k in item if k.lower() in header_set}
                for h in header_set:
                    cef_name = CIM_CEF_MAP.get(h, h)
                    cef_name = name_mappings.get(cef_name, cef_name)
                    cef_key_value = name_mappings.get(h, h)
                    cef[cef_name] = item.get(cef_key_value)
                    if include_cim_fields:
                        cef[cef_key_value] = item.get(cef_key_value)
            else:
                for k, v in item.items():
                    cef[CIM_CEF_MAP.get(k, k)] = v
                    if include_cim_fields:
                        cef[k] = v

            if use_event_id_sdi and "event_id" in item:
                sdi = item["event_id"]
            else:
                if use_event_id_sdi and "event_id" not in item:
                    logger.warning(
                        "use_event_id_sdi enabled but event_id missing, using hash"
                    )
                input_str = UnicodeDammit(json.dumps(item)).unicode_markup.encode(
                    "utf-8"
                )
                if _get_fips_enabled():
                    sdi = hashlib.sha256(input_str).hexdigest()
                else:
                    sdi = hashlib.md5(input_str).hexdigest()  # noqa: S324

            severity = _get_splunk_severity(item)
            spl_event_start = _get_event_start(item.get("_time"))
            container_name = _get_splunk_title(
                item, container_name_prefix, container_name_values
            )

            yield Container(
                name=container_name,
                severity=severity,
                source_data_identifier=sdi,
            )

            if asset.remove_empty_cef:
                cef = {k: v for k, v in cef.items() if v is not None}

            yield Artifact(
                cef=cef,
                name="Field Values",
                source_data_identifier=sdi,
                severity=severity,
                start_time=spl_event_start,
                run_automation=True,
            )

            if count == asset.container_update_state and not is_poll_now:
                state["start_time"] = item.get("_indextime")
                count = 0
            count += 1

        except Exception as e:
            logger.error("Error processing event: %s", e)
            continue

    if data and not is_poll_now:
        state["start_time"] = data[-1].get("_indextime")
