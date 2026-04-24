# Copyright (c) 2016-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import hashlib
import json
import os
import re
import ssl
import sys
import time
from collections.abc import Iterator
from datetime import datetime, UTC
from dateutil.parser import ParserError, parse as dateutil_parse
from io import BytesIO
from urllib.error import HTTPError as UrllibHTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener, install_opener, urlopen
from zoneinfo import ZoneInfo

import requests
import splunklib.binding as splunk_binding
import splunklib.client as splunk_client
import splunklib.results as splunk_results
from splunklib.binding import HTTPError as SplunkHTTPError
import xmltodict
from bs4 import BeautifulSoup
from bs4.dammit import UnicodeDammit
from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField, PermissiveActionOutput
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger
from soar_sdk.models.artifact import Artifact
from soar_sdk.models.container import Container
from soar_sdk.params import OnPollParams, Param, Params

from .splunk_consts import (
    CIM_CEF_MAP,
    SPLUNK_DEFAULT_REQUEST_TIMEOUT,
    SPLUNK_DEFAULT_SOURCE,
    SPLUNK_DEFAULT_SOURCE_TYPE,
    SPLUNK_DISPOSITION_QUERY_FORMAT,
    SPLUNK_ERR_BAD_DISPOSITION,
    SPLUNK_ERR_BAD_STATUS,
    SPLUNK_ERR_CONNECTIVITY_FAILED,
    SPLUNK_ERR_CONNECTIVITY_TEST,
    SPLUNK_ERR_EMPTY_RESPONSE,
    SPLUNK_ERR_INVALID_INTEGER,
    SPLUNK_ERR_INVALID_SLEEP_TIME,
    SPLUNK_ERR_NEED_PARAM,
    SPLUNK_ERR_NON_NEGATIVE_INTEGER,
    SPLUNK_ERR_NOT_ES,
    SPLUNK_ERR_INVALID_PARAM,
    SPLUNK_ERR_REQUIRED_CONFIG_PARAMS,
    SPLUNK_ERR_SPLUNK_JOB_HAS_TIMED_OUT,
    SPLUNK_ERR_UNABLE_TO_CREATE_JOB,
    SPLUNK_ERR_UNABLE_TO_PARSE_HTML_RESPONSE,
    SPLUNK_ERR_UNABLE_TO_PARSE_JSON_RESPONSE,
    SPLUNK_EXCEPTION_ERR_MESSAGE,
    SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE,
    SPLUNK_PROG_CREATED_QUERY,
    SPLUNK_PROG_CREATING_SEARCH_JOB,
    SPLUNK_RID_SID_NOTABLE_QUERY,
    SPLUNK_SEARCH_MODE_SMART,
    SPLUNK_SEVERITY_MAP,
    SPLUNK_SUCCESS_CONNECTIVITY_TEST,
)

logger = getLogger()


# ---------------------------------------------------------------------------
# Asset
# ---------------------------------------------------------------------------
class Asset(BaseAsset):
    device: str = AssetField(
        required=True,
        description="Device IP/Hostname",
        category=FieldCategory.CONNECTIVITY,
    )
    port: int = AssetField(
        description="Port",
        required=False,
        default=8089,
        category=FieldCategory.CONNECTIVITY,
    )
    username: str = AssetField(
        description="Username",
        required=False,
        default="",
        category=FieldCategory.CONNECTIVITY,
    )
    password: str = AssetField(
        description="Password",
        required=False,
        default="",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    api_token: str = AssetField(
        description="API token",
        required=False,
        default="",
        sensitive=True,
        category=FieldCategory.CONNECTIVITY,
    )
    splunk_owner: str = AssetField(
        description="The owner context of the namespace",
        required=False,
        default="",
        category=FieldCategory.CONNECTIVITY,
    )
    splunk_app: str = AssetField(
        description="The app context of the namespace",
        required=False,
        default="",
        category=FieldCategory.CONNECTIVITY,
    )
    timezone: str = AssetField(
        required=False,
        default="UTC",
        description="Splunk Server Timezone",
        category=FieldCategory.CONNECTIVITY,
    )
    verify_server_cert: bool = AssetField(
        description="Verify Server Certificate",
        required=False,
        default=False,
        category=FieldCategory.CONNECTIVITY,
    )

    # Ingestion fields
    on_poll_command: str = AssetField(
        description="Command for query to use with On Poll",
        required=False,
        default="",
        value_list=["", "search", "eval", "savedsearch", "stats", "table", "tstats"],
        category=FieldCategory.INGEST,
    )
    on_poll_query: str = AssetField(
        description="Query to use with On Poll",
        required=False,
        default="",
        category=FieldCategory.INGEST,
    )
    on_poll_display: str = AssetField(
        description="Fields to save with On Poll",
        required=False,
        default="",
        category=FieldCategory.INGEST,
    )
    on_poll_parse_only: bool = AssetField(
        description="Parse Only",
        required=False,
        default=True,
        category=FieldCategory.INGEST,
    )
    max_container: int = AssetField(
        description="Max events to ingest for Scheduled Polling (Default: 100)",
        required=False,
        default=100,
        category=FieldCategory.INGEST,
    )
    container_update_state: int = AssetField(
        description="Container count to update the state file",
        required=False,
        default=100,
        category=FieldCategory.INGEST,
    )
    container_name_prefix: str = AssetField(
        description="Name to give containers created via ingestion",
        required=False,
        default="",
        category=FieldCategory.INGEST,
    )
    container_name_values: str = AssetField(
        description="Values to append to container name",
        required=False,
        default="",
        category=FieldCategory.INGEST,
    )
    retry_count: int = AssetField(
        description="Number of retries",
        required=False,
        default=3,
        category=FieldCategory.CONNECTIVITY,
    )
    remove_empty_cef: bool = AssetField(
        description="Remove CEF fields having empty values from the artifact",
        required=False,
        default=False,
        category=FieldCategory.INGEST,
    )
    sleeptime_in_requests: int = AssetField(
        description="The time to wait for next REST call (max 120 seconds)",
        required=False,
        default=1,
        category=FieldCategory.CONNECTIVITY,
    )
    include_cim_fields: bool = AssetField(
        description="Option to keep original Splunk CIM together with SOAR CEF fields",
        required=False,
        default=False,
        category=FieldCategory.INGEST,
    )
    splunk_job_timeout: int = AssetField(
        description="The duration in seconds to wait before a scheduled Splunk job times out",
        required=False,
        default=1200,
        category=FieldCategory.CONNECTIVITY,
    )
    use_event_id_sdi: bool = AssetField(
        description="Option to use the event_id field value as the source data identifier instead of the full event hash",
        required=False,
        default=False,
        category=FieldCategory.INGEST,
    )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = App(
    name="Splunk",
    app_type="siem",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Splunk Inc.",
    product_name="Splunk Enterprise",
    publisher="Splunk",
    appid="91883aa8-9c81-470b-97a1-5d8f7995f560",
    fips_compliant=True,
    asset_cls=Asset,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
class SplunkHelper:
    """Manages the Splunk SDK connection and REST calls."""

    def __init__(self, asset: Asset):
        self.asset = asset
        self._service: splunk_client.Service | None = None
        self._base_url = f"https://{asset.device}:{asset.port}/"
        self._proxy: dict[str, str] = {}

        if "http_proxy" in os.environ:
            self._proxy["http"] = os.environ["http_proxy"]
        elif "HTTP_PROXY" in os.environ:
            self._proxy["http"] = os.environ["HTTP_PROXY"]

        if "https_proxy" in os.environ:
            self._proxy["https"] = os.environ["https_proxy"]
        elif "HTTPS_PROXY" in os.environ:
            self._proxy["https"] = os.environ["HTTPS_PROXY"]

    # -- validation ----------------------------------------------------------
    @staticmethod
    def validate_integer(value, name: str, allow_zero: bool = False) -> int | None:
        if value is None or value == "":
            return None
        try:
            if not float(value).is_integer():
                raise ValueError(SPLUNK_ERR_INVALID_INTEGER.format(param=name))
            value = int(value)
        except (ValueError, TypeError):
            raise ValueError(SPLUNK_ERR_INVALID_INTEGER.format(param=name)) from None

        if value < 0:
            raise ValueError(SPLUNK_ERR_NON_NEGATIVE_INTEGER.format(param=name))
        if not allow_zero and value == 0:
            raise ValueError(SPLUNK_ERR_INVALID_PARAM.format(param=name))
        return value

    def validate_asset(self):
        if not self.asset.api_token and (not self.asset.username or not self.asset.password):
            raise ValueError(SPLUNK_ERR_REQUIRED_CONFIG_PARAMS)

        self.validate_integer(self.asset.retry_count, "'retry_count' configuration")
        self.validate_integer(self.asset.port, "'port' configuration")
        self.validate_integer(self.asset.max_container, "'max_container' configuration", allow_zero=True)
        self.validate_integer(self.asset.container_update_state, "'Container count to update the state file' configuration")
        self.validate_integer(self.asset.splunk_job_timeout, "'splunk_job_timeout' configuration")
        self.validate_integer(self.asset.sleeptime_in_requests, "'sleeptime_in_requests' configuration")

        if self.asset.sleeptime_in_requests > 120:
            raise ValueError(SPLUNK_ERR_INVALID_SLEEP_TIME.format(param="'sleeptime_in_requests'"))

    # -- proxy handler for splunklib ----------------------------------------
    def _proxy_request(self, url, message, **kwargs):
        method = message["method"].lower()
        data = message.get("body", "") if method == "post" else None
        headers = dict(message.get("headers", []))
        req = Request(url, data, headers)  # noqa: S310
        try:
            response = urlopen(req)  # noqa: S310
        except UrllibHTTPError:
            logger.warning("Check the proxy settings")
            raise
        except URLError:
            if sys.version_info >= (2, 7, 9) and not self.asset.verify_server_cert:
                response = urlopen(req, context=ssl._create_unverified_context())  # noqa: S310, S323
            else:
                raise
        return {
            "status": response.code,
            "reason": response.msg,
            "headers": response.getheaders(),
            "body": BytesIO(response.read()),
        }

    def _make_proxy_handler(self, proxy: str):
        proxy_handler = ProxyHandler({"http": proxy, "https": proxy})
        opener = build_opener(proxy_handler)
        install_opener(opener)
        return self._proxy_request

    # -- connection ----------------------------------------------------------
    def connect(self):
        if self._service is not None:
            return

        kwargs_config = {
            "host": self.asset.device,
            "port": self.asset.port,
            "username": self.asset.username,
            "password": self.asset.password,
            "owner": self.asset.splunk_owner or None,
            "app": self.asset.splunk_app or None,
            "verify": self.asset.verify_server_cert,
        }

        if self.asset.api_token:
            logger.info("Using token-based authentication")
            kwargs_config["splunkToken"] = self.asset.api_token
            kwargs_config.pop("username", None)
            kwargs_config.pop("password", None)

        proxy_param = self._proxy.get("https") or self._proxy.get("http")

        no_proxy = os.environ.get("no_proxy", os.environ.get("NO_PROXY", ""))
        if self.asset.device in no_proxy.split(","):
            proxy_param = None

        try:
            if proxy_param:
                logger.info("Engaging proxy")
                self._service = splunk_client.connect(
                    handler=self._make_proxy_handler(proxy_param), **kwargs_config
                )
            else:
                self._service = splunk_client.connect(**kwargs_config)
        except splunk_binding.HTTPError as e:
            error_text = str(e)
            if "405 Method Not Allowed" in error_text:
                raise ConnectionError("Error occurred while connecting to the Splunk server") from e
            raise ConnectionError(f"Error occurred while connecting to the Splunk server. Details: {error_text}") from e
        except Exception as e:
            raise ConnectionError(
                SPLUNK_EXCEPTION_ERR_MESSAGE.format(msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=e)
            ) from e

    @property
    def service(self) -> splunk_client.Service:
        if self._service is None:
            self.connect()
        return self._service

    # -- REST calls ----------------------------------------------------------
    def make_rest_call(self, endpoint: str, data, params: dict | None = None, method=requests.post) -> dict:
        url = f"{self._base_url}services/{endpoint}"
        logger.debug("Making REST call to %s", url)

        auth, auth_headers = None, None
        if self.asset.api_token:
            auth_headers = {"Authorization": f"Bearer {self.asset.api_token}"}
        else:
            auth = (self.asset.username, self.asset.password)

        try:
            r = method(
                url,
                data=data,
                params=params or {},
                auth=auth,
                headers=auth_headers,
                verify=self.asset.verify_server_cert,
                timeout=SPLUNK_DEFAULT_REQUEST_TIMEOUT,
            )
        except Exception as e:
            raise ConnectionError(
                SPLUNK_EXCEPTION_ERR_MESSAGE.format(msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=e)
            ) from e

        return self._process_response(r)

    def make_rest_call_retry(self, endpoint: str, data, params: dict | None = None, method=requests.post) -> dict:
        last_err = None
        for _ in range(self.asset.retry_count):
            try:
                return self.make_rest_call(endpoint, data, params, method)
            except Exception as e:
                last_err = e
        raise last_err  # type: ignore[misc]

    # -- response processing -------------------------------------------------
    def _process_response(self, r: requests.Response) -> dict:
        content_type = r.headers.get("Content-Type", "")
        if "json" in content_type:
            return self._process_json_response(r)
        if "html" in content_type:
            return self._process_html_response(r)
        if "xml" in content_type:
            return self._process_xml_response(r)
        if not r.text:
            return self._process_empty_response(r)

        error_text = r.text.replace("{", "{{").replace("}", "}}")
        raise RuntimeError(
            f"Can't process response from server. Status Code: {r.status_code} Data from server: {error_text}"
        )

    @staticmethod
    def _process_empty_response(r: requests.Response) -> dict:
        if r.status_code in (200, 204):
            return {}
        raise RuntimeError(SPLUNK_ERR_EMPTY_RESPONSE.format(code=r.status_code))

    @staticmethod
    def _process_xml_response(r: requests.Response) -> dict:
        try:
            resp_json = xmltodict.parse(r.text) if r.text else None
        except Exception as e:
            raise RuntimeError(f"Unable to parse XML response. Error: {e}") from e

        if 200 <= r.status_code < 400:
            return resp_json or {}

        error_type = resp_json.get("response", {}).get("messages", {}).get("msg", {}).get("@type") if resp_json else None
        error_message = resp_json.get("response", {}).get("messages", {}).get("msg", {}).get("#text") if resp_json else None
        if error_type or error_message:
            error = f"ErrorType: {error_type} ErrorMessage: {error_message}"
        else:
            error = "Unable to parse xml response"
        raise RuntimeError(f"Error from server. Status Code: {r.status_code} Data from server: {error}")

    @staticmethod
    def _process_html_response(r: requests.Response) -> dict:
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = "\n".join(line.strip() for line in soup.text.split("\n") if line.strip())
        except Exception as e:
            error_text = SPLUNK_ERR_UNABLE_TO_PARSE_HTML_RESPONSE.format(error=e)

        if not error_text:
            error_text = "Empty response and no information received"

        message = f"Status Code: {r.status_code}. Data from server:\n{error_text}\n"
        if len(message) > 500:
            message = "Error occurred while connecting to the Splunk server"
        raise RuntimeError(message)

    @staticmethod
    def _process_json_response(r: requests.Response) -> dict:
        try:
            resp_json = r.json()
        except Exception as e:
            raise RuntimeError(SPLUNK_ERR_UNABLE_TO_PARSE_JSON_RESPONSE.format(error=e)) from e

        if 200 <= r.status_code < 399:
            return resp_json

        if isinstance(resp_json, str):
            raise RuntimeError(f"Error from server. Details: {resp_json}")
        if resp_json.get("error") or resp_json.get("error_description"):
            raise RuntimeError(
                f"Error from server. Status Code: {r.status_code}. "
                f"Error: {resp_json.get('error', 'Unavailable')}. "
                f"Error Details: {resp_json.get('error_description', 'Unavailable')}"
            )
        if resp_json.get("messages") and resp_json["messages"]:
            msg = resp_json["messages"][0]
            error = f"ErrorType: {msg.get('type')} ErrorMessage: {msg.get('text')}"
            raise RuntimeError(f"Error from server. Status Code: {r.status_code} Data from server: {error}")

        error_text = r.text.replace("{", "{{").replace("}", "}}")
        raise RuntimeError(f"Error from server. Status Code: {r.status_code}. Data from server: {error_text}")

    # -- server info ---------------------------------------------------------
    def get_server_version(self) -> str:
        try:
            resp = self.make_rest_call_retry(
                "authentication/users?output_mode=json", {}, method=requests.get
            )
        except Exception:
            return "FAILURE"
        return resp.get("generator", {}).get("version", "UNKNOWN")

    def check_for_es(self) -> bool:
        try:
            resp = self.make_rest_call_retry(
                "apps/local/SplunkEnterpriseSecuritySuite", {}, method=requests.get
            )
            return bool(resp)
        except Exception:
            return False

    # -- splunk search jobs --------------------------------------------------
    def create_job(self, search_query: str, kwargs_create: dict) -> splunk_client.Job:
        last_err = None
        for attempt in range(1, self.asset.retry_count + 1):
            try:
                return self.service.jobs.create(search_query, **kwargs_create)
            except Exception as e:
                logger.debug("Attempt %d to create splunk job failed: %s", attempt, e)
                last_err = e
        raise RuntimeError(
            SPLUNK_EXCEPTION_ERR_MESSAGE.format(msg=SPLUNK_ERR_UNABLE_TO_CREATE_JOB, error_text=last_err)
        )

    def wait_for_job(self, job: splunk_client.Job):
        last_err = None
        for attempt in range(1, self.asset.retry_count + 1):
            try:
                max_wait = time.time() + self.asset.splunk_job_timeout
                while not job.is_ready():
                    if time.time() > max_wait:
                        raise TimeoutError(SPLUNK_ERR_SPLUNK_JOB_HAS_TIMED_OUT)
                    time.sleep(self.asset.sleeptime_in_requests)
                job.refresh()
                return
            except TimeoutError:
                raise
            except Exception as e:
                logger.debug("Attempt %d to wait for job failed: %s", attempt, e)
                last_err = e
        raise RuntimeError(
            SPLUNK_EXCEPTION_ERR_MESSAGE.format(msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=last_err)
        )

    def get_job_stats(self, job) -> dict:
        return {
            "is_done": job["isDone"] if "isDone" in job else "Unknown status",
            "progress": float(job["doneProgress"]) * 100 if "doneProgress" in job else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Done progress"),
            "scan_count": int(job["scanCount"]) if "scanCount" in job else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Scan count"),
            "event_count": int(job["eventCount"]) if "eventCount" in job else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Event count"),
            "result_count": int(job["resultCount"]) if "resultCount" in job else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Result count"),
        }

    def validate_query(self, search_query: str, parse_only: bool = True):
        for attempt in range(self.asset.retry_count):
            try:
                self.service.parse(search_query, parse_only=parse_only)
                return
            except SplunkHTTPError as e:
                self._service = None
                self.connect()
                if attempt == self.asset.retry_count - 1:
                    raise ValueError(
                        SPLUNK_EXCEPTION_ERR_MESSAGE.format(msg=f"Query invalid '{search_query}'", error_text=e)
                    ) from e
            except Exception as e:
                self._service = None
                self.connect()
                if attempt == self.asset.retry_count - 1:
                    raise RuntimeError(
                        SPLUNK_EXCEPTION_ERR_MESSAGE.format(msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=e)
                    ) from e

    def run_query(self, search_query: str, kwargs_create: dict | None = None, parse_only: bool = True, add_raw_field: bool = True) -> tuple[str, list[dict]]:
        if kwargs_create is None:
            kwargs_create = {}

        self.validate_query(search_query, parse_only)
        logger.debug(SPLUNK_PROG_CREATED_QUERY.format(query=search_query))
        logger.progress(SPLUNK_PROG_CREATING_SEARCH_JOB)

        kwargs_create["exec_mode"] = "normal"
        job = self.create_job(search_query, kwargs_create)
        sid = job.__dict__.get("sid", "")

        while True:
            self.wait_for_job(job)
            stats = self.get_job_stats(job)
            if stats["is_done"] == "1":
                break
            time.sleep(self.asset.sleeptime_in_requests)

        results_list: list[dict] = []

        try:
            results = splunk_results.JSONResultsReader(
                job.results(count=kwargs_create.get("max_count", 0), output_mode="json")
            )
        except Exception as e:
            raise RuntimeError(
                SPLUNK_EXCEPTION_ERR_MESSAGE.format(msg="Error retrieving results", error_text=e)
            ) from e

        for result in results:
            if not isinstance(result, dict):
                continue
            if not add_raw_field:
                result.pop("_raw", None)
            results_list.append(result)

        return sid, results_list

    def resolve_event_id(self, sidandrid: str) -> str:
        logger.progress("Resolving SID+RID to event_id")
        search_query = SPLUNK_RID_SID_NOTABLE_QUERY.format(sidandrid)
        _sid, results = self.run_query(search_query)
        for row in results:
            if "event_id" in row:
                return row["event_id"]
        raise RuntimeError("could not find event_id of splunk event")

    def get_status_dict(self, status_type: str) -> dict[str, int]:
        splunk_dict: dict[str, int] = {}
        try:
            resp = self.make_rest_call_retry(
                "alerts/reviewstatuses?count=-1&output_mode=json", {}, method=requests.get
            )
        except Exception:
            return splunk_dict

        for data in resp.get("entry", []):
            obj_id = data.get("name", "").split(":")[-1]
            obj_name = data.get("content", {}).get("label")
            is_enabled = str(data.get("content", {}).get("disabled")) == "0"
            is_type = data.get("content", {}).get("status_type") == status_type
            if obj_id and obj_id.isdigit() and obj_name and is_enabled and is_type:
                key = obj_name.lower() if status_type == "notable" else obj_name
                splunk_dict[key] = int(obj_id)
        return splunk_dict

    def get_tz_str_from_epoch(self, fmt: str, epoch_milli: int) -> str:
        to_tz = ZoneInfo(self.asset.timezone)
        utc_dt = datetime.fromtimestamp(epoch_milli // 1000, tz=UTC)
        return utc_dt.astimezone(to_tz).strftime(fmt)


# ---------------------------------------------------------------------------
# Ingestion helpers
# ---------------------------------------------------------------------------
def _get_event_start(start_time: str | None) -> str | None:
    if not start_time:
        return None
    try:
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
        from phantom_common.install_info import is_fips_enabled  # noqa: PLC0415
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


# ---------------------------------------------------------------------------
# Params / Outputs
# ---------------------------------------------------------------------------
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


class UpdateEventParams(Params):
    event_ids: str = Param(
        description="Event ID to update",
        required=True,
        primary=True,
        cef_types=["splunk notable event id"],
    )
    owner: str = Param(description="New owner for the event", required=False, default="")
    status: str = Param(
        description="New status for the event",
        required=False,
        default="",
        value_list=["", "unassigned", "new", "in progress", "pending", "resolved", "closed"],
    )
    integer_status: str = Param(description="Integer representing custom status value", required=False, default="")
    urgency: str = Param(
        description="New urgency for the event",
        required=False,
        default="",
        value_list=["", "informational", "low", "medium", "high", "critical"],
    )
    comment: str = Param(description="New comment for the event", required=False, default="")
    disposition: str = Param(
        description="New disposition field",
        required=False,
        default="",
        value_list=[
            "", "Unassigned", "True Positive - Suspicious Activity",
            "Benign Positive - Suspicious But Expected",
            "False Positive - Incorrect Analytic Logic",
            "False Positive - Inaccurate Data", "Undetermined", "Other",
        ],
    )
    integer_disposition: str = Param(description="Integer representing custom disposition value", required=False, default="")
    wait_for_confirmation: bool = Param(description="Validate event_ids", required=False, default=False)


class UpdateEventOutput(ActionOutput):
    status: str | None = OutputField(column_name="Status")
    failure_count: int | None = None
    message: str | None = OutputField(column_name="Message")
    success: bool | None = None
    success_count: int | None = None


class UpdateEventSummary(ActionOutput):
    sid: str | None = None
    updated_event_id: str | None = None


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


# ---------------------------------------------------------------------------
# Custom view for run query
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Test Connectivity
# ---------------------------------------------------------------------------
@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    helper = SplunkHelper(asset)
    helper.validate_asset()

    try:
        helper.connect()
    except Exception as e:
        soar.set_message(SPLUNK_ERR_CONNECTIVITY_TEST)
        raise RuntimeError(f"{SPLUNK_ERR_CONNECTIVITY_TEST}: {e}") from e

    version = helper.get_server_version()
    if version == "FAILURE":
        soar.set_message(SPLUNK_ERR_CONNECTIVITY_TEST)
        raise RuntimeError(SPLUNK_ERR_CONNECTIVITY_TEST)

    is_es = helper.check_for_es()
    logger.progress("Detected Splunk %sserver version %s", "ES " if is_es else "", version)
    soar.set_message(SPLUNK_SUCCESS_CONNECTIVITY_TEST)
    logger.info(SPLUNK_SUCCESS_CONNECTIVITY_TEST)


# ---------------------------------------------------------------------------
# Run Query
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Get Host Events
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Update Event
# ---------------------------------------------------------------------------
@app.action(
    description="Update a notable event",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateEventSummary,
)
def update_event(params: UpdateEventParams, soar: SOARClient, asset: Asset) -> list[UpdateEventOutput]:
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

    if not any([comment, status, urgency, owner, disposition]) and integer_status is None and integer_disposition is None:
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
            raise RuntimeError("Unable to find underlying event_id from SID + RID combo") from None

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
        request_body["disposition"] = SPLUNK_DISPOSITION_QUERY_FORMAT.format(integer_disposition)
    elif disposition:
        if disposition not in splunk_disposition_dict:
            if not disposition.isdigit():
                raise ValueError(SPLUNK_ERR_BAD_DISPOSITION)
            request_body["disposition"] = SPLUNK_DISPOSITION_QUERY_FORMAT.format(disposition)
        else:
            request_body["disposition"] = SPLUNK_DISPOSITION_QUERY_FORMAT.format(splunk_disposition_dict[disposition])

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


# ---------------------------------------------------------------------------
# Post Data
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# On Poll
# ---------------------------------------------------------------------------
@app.on_poll()
def on_poll(params: OnPollParams, soar: SOARClient, asset: Asset) -> Iterator[Container | Artifact]:
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
        _sid, results_list = helper.run_query(search_query, kwargs_create=search_params, parse_only=po)
    except Exception as e:
        msg = str(e)
        if "Invalid index_earliest" in msg:
            logger.debug("Invalid start_time %s, retrying without it", search_params.get("index_earliest"))
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
    container_name_values = [x.strip() for x in raw_values.split(",")] if raw_values else []

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
                    logger.warning("use_event_id_sdi enabled but event_id missing, using hash")
                input_str = UnicodeDammit(json.dumps(item)).unicode_markup.encode("utf-8")
                if _get_fips_enabled():
                    sdi = hashlib.sha256(input_str).hexdigest()
                else:
                    sdi = hashlib.md5(input_str).hexdigest()  # noqa: S324

            severity = _get_splunk_severity(item)
            spl_event_start = _get_event_start(item.get("_time"))
            container_name = _get_splunk_title(item, container_name_prefix, container_name_values)

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


if __name__ == "__main__":
    app.cli()
