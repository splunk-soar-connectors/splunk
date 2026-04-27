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

import os
import ssl
import sys
import time
from datetime import UTC, datetime
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
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.asset import AssetField, BaseAsset, FieldCategory
from soar_sdk.logging import getLogger

from .splunk_consts import (
    SPLUNK_DEFAULT_REQUEST_TIMEOUT,
    SPLUNK_ERR_CONNECTIVITY_FAILED,
    SPLUNK_ERR_CONNECTIVITY_TEST,
    SPLUNK_ERR_EMPTY_RESPONSE,
    SPLUNK_ERR_INVALID_INTEGER,
    SPLUNK_ERR_INVALID_SLEEP_TIME,
    SPLUNK_ERR_INVALID_PARAM,
    SPLUNK_ERR_NON_NEGATIVE_INTEGER,
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
        if not self.asset.api_token and (
            not self.asset.username or not self.asset.password
        ):
            raise ValueError(SPLUNK_ERR_REQUIRED_CONFIG_PARAMS)

        self.validate_integer(self.asset.retry_count, "'retry_count' configuration")
        self.validate_integer(self.asset.port, "'port' configuration")
        self.validate_integer(
            self.asset.max_container, "'max_container' configuration", allow_zero=True
        )
        self.validate_integer(
            self.asset.container_update_state,
            "'Container count to update the state file' configuration",
        )
        self.validate_integer(
            self.asset.splunk_job_timeout, "'splunk_job_timeout' configuration"
        )
        self.validate_integer(
            self.asset.sleeptime_in_requests, "'sleeptime_in_requests' configuration"
        )

        if self.asset.sleeptime_in_requests > 120:
            raise ValueError(
                SPLUNK_ERR_INVALID_SLEEP_TIME.format(param="'sleeptime_in_requests'")
            )

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
                raise ConnectionError(
                    "Error occurred while connecting to the Splunk server"
                ) from e
            raise ConnectionError(
                f"Error occurred while connecting to the Splunk server. Details: {error_text}"
            ) from e
        except Exception as e:
            raise ConnectionError(
                SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                    msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=e
                )
            ) from e

    @property
    def service(self) -> splunk_client.Service:
        if self._service is None:
            self.connect()
        return self._service

    # -- REST calls ----------------------------------------------------------
    def make_rest_call(
        self, endpoint: str, data, params: dict | None = None, method=requests.post
    ) -> dict:
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
                SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                    msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=e
                )
            ) from e

        return self._process_response(r)

    def make_rest_call_retry(
        self, endpoint: str, data, params: dict | None = None, method=requests.post
    ) -> dict:
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

        error_type = (
            resp_json.get("response", {})
            .get("messages", {})
            .get("msg", {})
            .get("@type")
            if resp_json
            else None
        )
        error_message = (
            resp_json.get("response", {})
            .get("messages", {})
            .get("msg", {})
            .get("#text")
            if resp_json
            else None
        )
        if error_type or error_message:
            error = f"ErrorType: {error_type} ErrorMessage: {error_message}"
        else:
            error = "Unable to parse xml response"
        raise RuntimeError(
            f"Error from server. Status Code: {r.status_code} Data from server: {error}"
        )

    @staticmethod
    def _process_html_response(r: requests.Response) -> dict:
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = "\n".join(
                line.strip() for line in soup.text.split("\n") if line.strip()
            )
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
            raise RuntimeError(
                SPLUNK_ERR_UNABLE_TO_PARSE_JSON_RESPONSE.format(error=e)
            ) from e

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
            raise RuntimeError(
                f"Error from server. Status Code: {r.status_code} Data from server: {error}"
            )

        error_text = r.text.replace("{", "{{").replace("}", "}}")
        raise RuntimeError(
            f"Error from server. Status Code: {r.status_code}. Data from server: {error_text}"
        )

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
            SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                msg=SPLUNK_ERR_UNABLE_TO_CREATE_JOB, error_text=last_err
            )
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
            SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=last_err
            )
        )

    def get_job_stats(self, job) -> dict:
        return {
            "is_done": job["isDone"] if "isDone" in job else "Unknown status",  # noqa: SIM401 - job is a splunklib Entity, not a dict
            "progress": float(job["doneProgress"]) * 100
            if "doneProgress" in job
            else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Done progress"),
            "scan_count": int(job["scanCount"])
            if "scanCount" in job
            else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Scan count"),
            "event_count": int(job["eventCount"])
            if "eventCount" in job
            else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Event count"),
            "result_count": int(job["resultCount"])
            if "resultCount" in job
            else SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Result count"),
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
                        SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                            msg=f"Query invalid '{search_query}'", error_text=e
                        )
                    ) from e
            except Exception as e:
                self._service = None
                self.connect()
                if attempt == self.asset.retry_count - 1:
                    raise RuntimeError(
                        SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                            msg=SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=e
                        )
                    ) from e

    def run_query(
        self,
        search_query: str,
        kwargs_create: dict | None = None,
        parse_only: bool = True,
        add_raw_field: bool = True,
    ) -> tuple[str, list[dict]]:
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
                SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                    msg="Error retrieving results", error_text=e
                )
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
                "alerts/reviewstatuses?count=-1&output_mode=json",
                {},
                method=requests.get,
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
    logger.progress(
        "Detected Splunk %sserver version %s", "ES " if is_es else "", version
    )
    soar.set_message(SPLUNK_SUCCESS_CONNECTIVITY_TEST)
    logger.info(SPLUNK_SUCCESS_CONNECTIVITY_TEST)


if __name__ == "__main__":
    app.cli()
