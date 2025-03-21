# File: splunk_connector.py
#
# Copyright (c) 2016-2025 Splunk Inc.
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
#

import hashlib
import json
import os
import re
import ssl
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional
from urllib.error import HTTPError as UrllibHTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener, install_opener, urlopen
from zoneinfo import ZoneInfo

import phantom.app as phantom
import phantom.rules as soar_vault
import requests
import splunklib.binding as splunk_binding
import splunklib.client as splunk_client
import splunklib.results as splunk_results
import xmltodict
from bs4 import BeautifulSoup
from bs4.dammit import UnicodeDammit
from dateutil.parser import ParserError, parse as dateutil_parse
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
from splunklib.binding import HTTPError

import splunk_consts as consts


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SplunkConnector(BaseConnector):
    ACTION_ID_POST_DATA = "post_data"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_UPDATE_EVENT = "update_event"
    ACTION_ID_GET_HOST_EVENTS = "get_host_events"

    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()
        self._service = None
        self._base_url = None
        self.splunk_server = None
        self.retry_count = None
        self.port = None
        self.max_container = None
        self._splunk_status_dict = None
        self._splunk_disposition_dict = None
        self.container_update_state = None
        self.remove_empty_cef = None
        self.sleeptime_in_requests = None

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """
        error_code = None
        error_message = consts.SPLUNK_ERR_MESSAGE_UNAVAILABLE

        self.error_print(f"Traceback: {traceback.format_stack()}")
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_message = e.args[1]
                elif len(e.args) == 1:
                    error_message = e.args[0]
            else:
                error_message = consts.SPLUNK_ERR_MESSAGE_UNAVAILABLE

            if error_message == consts.SPLUNK_ERR_MESSAGE_UNAVAILABLE:
                error_message = str(e).strip().replace("'", "").replace('"', "").replace("\n", "").replace("\r", "")
                if len(error_message) > 500:
                    error_message = f"{error_message[:500]} - truncated"
                error_message = f"{error_message} ({sys.exc_info()[-1].tb_lineno})"
        except Exception as e:
            self._dump_error_log(e, "Error occurred while fetching exception information")

            if not error_code:
                error_message = f"Error Message: {error_message}"
            else:
                error_message = f"Error Code: {error_code}. Error Message: {error_message}"

        return error_message

    def initialize(self):
        config = self.get_config()

        self.splunk_server = config[phantom.APP_JSON_DEVICE]

        self._username = config.get(phantom.APP_JSON_USERNAME)
        self._password = config.get(phantom.APP_JSON_PASSWORD)
        self._api_token = config.get(consts.SPLUNK_JSON_API_KEY)

        self._base_url = f"https://{self.splunk_server}:{config.get(phantom.APP_JSON_PORT, 8089)}/"
        self._state = self.load_state()
        if not isinstance(self._state, dict):
            self.debug_print("State file format is not valid")
            self._state = {}
            self.save_state(self._state)
            self.debug_print("Recreated the state file with current app_version")
            self._state = self.load_state()
            if self._state is None:
                self.debug_print("Please check the owner, owner group, and the permissions of the state file")
                self.debug_print(
                    "The Splunk SOAR user should have correct access rights and ownership for the \
                    corresponding state file (refer readme file for more information)"
                )
                return phantom.APP_ERROR

        self._proxy = {}

        # Either username and password or API token must be provided
        if not self._api_token and (not self._username or not self._password):
            return self.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_REQUIRED_CONFIG_PARAMS)

        if "http_proxy" in os.environ:
            self._proxy["http"] = os.environ.get("http_proxy")
        elif "HTTP_PROXY" in os.environ:
            self._proxy["http"] = os.environ.get("HTTP_PROXY")

        if "https_proxy" in os.environ:
            self._proxy["https"] = os.environ.get("https_proxy")
        elif "HTTPS_PROXY" in os.environ:
            self._proxy["https"] = os.environ.get("HTTPS_PROXY")

        self._container_name_prefix = config.get("container_name_prefix", "")
        container_name_values = config.get("container_name_values")
        if container_name_values:
            self._container_name_values = [x.strip() for x in container_name_values.split(",")]
        else:
            self._container_name_values = []

        # Validate retry_count
        ret_val, self.retry_count = self._validate_integer(self, config.get("retry_count", 3), consts.SPLUNK_RETRY_COUNT_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate port
        ret_val, self.port = self._validate_integer(self, config.get("port", 8089), consts.SPLUNK_PORT_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate max_container
        ret_val, self.max_container = self._validate_integer(self, config.get("max_container", 100), consts.SPLUNK_MAX_CONTAINER_KEY, True)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate container_update_state
        ret_val, self.container_update_state = self._validate_integer(
            self, config.get("container_update_state", 100), consts.SPLUNK_CONTAINER_UPDATE_STATE_KEY
        )
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate splunk_job_timeout
        ret_val, self.splunk_job_timeout = self._validate_integer(self, config.get("splunk_job_timeout"), consts.SPLUNK_JOB_TIMEOUT_KEY)
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate sleeptime_in_requests
        ret_val, self.sleeptime_in_requests = self._validate_integer(
            self, config.get("sleeptime_in_requests", 1), consts.SPLUNK_SLEEPTIME_IN_REQUESTS_KEY
        )
        if phantom.is_fail(ret_val):
            return self.get_status()

        # Validate if user has entered more than 120 seconds
        if self.sleeptime_in_requests > 120:
            return self.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_SLEEP_TIME.format(param=consts.SPLUNK_SLEEPTIME_IN_REQUESTS_KEY))

        self.remove_empty_cef = config.get("remove_empty_cef", False)

        return phantom.APP_SUCCESS

    def finalize(self):
        if self._state is not None:
            self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _dump_error_log(self, error, message="Exception occurred."):
        self.error_print(message, dump_object=error)

    def request(self, url, message, **kwargs):
        """Splunk SDK Proxy handler"""
        method = message["method"].lower()
        config = self.get_config()
        data = message.get("body", "") if method == "post" else None
        headers = dict(message.get("headers", []))
        req = Request(url, data, headers)
        try:
            response = urlopen(req)
            self.debug_print(response)
        except URLError:
            # If running Python 2.7.9+, disable SSL certificate validation and try again
            if sys.version_info >= (2, 7, 9) and not config[phantom.APP_JSON_VERIFY]:
                response = urlopen(req, context=ssl._create_unverified_context())  # nosemgrep
            else:
                raise
        except UrllibHTTPError:
            self.save_progress("Check the proxy settings")
            pass  # Propagate HTTP errors via the returned response message
        return {"status": response.code, "reason": response.msg, "headers": response.getheaders(), "body": BytesIO(response.read())}

    def handler(self, proxy):
        """Splunk SDK Proxy Request Handler"""
        proxy_handler = ProxyHandler({"http": proxy, "https": proxy})
        opener = build_opener(proxy_handler)
        install_opener(opener)
        return self.request

    def _connect(self, action_result):
        if self._service is not None:
            return phantom.APP_SUCCESS

        config = self.get_config()

        kwargs_config_flags = {
            "host": self.splunk_server,
            "port": self.port,
            "username": self._username,
            "password": self._password,
            "owner": config.get("splunk_owner", None),
            "app": config.get("splunk_app", None),
        }

        # token-based authentication
        if self._api_token:
            self.save_progress("Using token-based authentication")
            kwargs_config_flags["splunkToken"] = self._api_token
            kwargs_config_flags.pop(phantom.APP_JSON_USERNAME)
            kwargs_config_flags.pop(phantom.APP_JSON_PASSWORD)

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, self.splunk_server)

        proxy_param = None

        if self._proxy.get("http", None) is not None:
            proxy_param = self._proxy.get("http")
        if self._proxy.get("https", None) is not None:
            proxy_param = self._proxy.get("https")

        no_proxy_host = os.environ.get("no_proxy", os.environ.get("NO_PROXY", ""))
        if self.splunk_server in no_proxy_host.split(","):
            pass
        elif self._api_token:
            if any(proxy_var in os.environ for proxy_var in ["HTTPS_PROXY", "https_proxy"]):
                self.save_progress("[-] Engaging Proxy")
        else:
            if any(proxy_var in os.environ for proxy_var in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"]):
                self.save_progress("[-] Engaging Proxy")

        try:
            if proxy_param:
                self._service = splunk_client.connect(handler=self.handler(proxy_param), **kwargs_config_flags)
            else:
                self._service = splunk_client.connect(**kwargs_config_flags)
        except splunk_binding.HTTPError as e:
            error_text = self._get_error_message_from_exception(e)
            self._dump_error_log(e, "Error occurred while connecting to the Splunk server.")
            if "405 Method Not Allowed" in error_text:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while connecting to the Splunk server")
            else:
                return action_result.set_status(
                    phantom.APP_ERROR, f"Error occurred while connecting to the Splunk server. Details: {error_text}"
                )
        except Exception as e:
            self._dump_error_log(e)
            error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                msg=consts.SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=self._get_error_message_from_exception(e)
            )
            return action_result.set_status(phantom.APP_ERROR, error_text)

        # Must return success if we want handle_action to be called
        return phantom.APP_SUCCESS

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_INTEGER.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_INTEGER.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NON_NEGATIVE_INTEGER.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_PARAM.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _make_rest_call_retry(self, action_result, endpoint, data, params=None, method=requests.post):
        if params is None:
            params = {}

        RETRY_LIMIT = self.retry_count

        for _ in range(0, RETRY_LIMIT):
            ret_val, resp_data = self._make_rest_call(action_result, endpoint, data, params, method)

            if not phantom.is_fail(ret_val):
                break
        return ret_val, resp_data

    def _make_rest_call(self, action_result, endpoint, data, params=None, method=requests.post):
        if params is None:
            params = {}

        config = self.get_config()
        url = f"{self._base_url}services/{endpoint}"
        self.debug_print(f"Making REST call to {url}")

        auth, auth_headers = None, None

        if self._api_token:
            # Splunk token-based authentication
            self.debug_print("Using token-based authentication")
            auth_headers = {"Authorization": f"Bearer {self._api_token}"}
        else:
            # Splunk username/password based authentication
            auth = (self._username, self._password)
        try:
            r = method(
                url,
                data=data,
                params=params,
                auth=auth,
                headers=auth_headers,
                verify=config[phantom.APP_JSON_VERIFY],
                timeout=consts.SPLUNK_DEFAULT_REQUEST_TIMEOUT,
            )
        except Exception as e:
            error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                msg=consts.SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=self._get_error_message_from_exception(e)
            )
            return action_result.set_status(phantom.APP_ERROR, error_text), None

        return self._process_response(r, action_result)

    def _process_response(self, r, action_result):
        """
        Process API response.

        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, "add_debug_data"):
            if r is not None:
                action_result.add_debug_data({"r_status_code": r.status_code})
                action_result.add_debug_data({"r_text": r.text})
                action_result.add_debug_data({"r_headers": r.headers})
            else:
                action_result.add_debug_data({"r_text": "r is None"})

        # Process each 'Content-Type' of response separately
        # Process a json response
        if "json" in r.headers.get("Content-Type", ""):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between Splunk SOAR and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if "html" in r.headers.get("Content-Type", ""):
            return self._process_html_response(r, action_result)

        if "xml" in r.headers.get("Content-Type", ""):
            return self._process_xml_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        error_text = r.text.replace("{", "{{").replace("}", "}}")
        message = f"Can't process response from server. Status Code: {r.status_code} Data from server: {error_text}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_empty_response(self, response, action_result):
        """
        Process empty response.

        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        if response.status_code == 200 or response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_EMPTY_RESPONSE.format(code=response.status_code)), None)

    def _process_xml_response(self, r, action_result):
        resp_json = None
        try:
            if r.text:
                resp_json = xmltodict.parse(r.text)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, f"Unable to parse XML response. Error: {error_message}"))

        if 200 <= r.status_code < 400:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        error_type = resp_json.get("response", {}).get("messages", {}).get("msg", {}).get("@type")
        error_message = resp_json.get("response", {}).get("messages", {}).get("msg", {}).get("#text")

        if error_type or error_message:
            error = f"ErrorType: {error_type} ErrorMessage: {error_message}"
        else:
            error = "Unable to parse xml response"

        message = f"Error from server. Status Code: {r.status_code} Data from server: {error}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), resp_json)

    def _process_html_response(self, response, action_result):
        """
        Process html response.

        :param response: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            # Remove the script, style, footer and navigation part from the HTML message
            for element in soup(["script", "style", "footer", "nav"]):
                element.extract()
            error_text = soup.text
            split_lines = error_text.split("\n")
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = "\n".join(split_lines)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            error_text = consts.SPLUNK_ERR_UNABLE_TO_PARSE_HTML_RESPONSE.format(error=error_message)

        if not error_text:
            error_text = "Empty response and no information received"
        message = f"Status Code: {status_code}. Data from server:\n{error_text}\n"

        message = message.replace("{", "{{").replace("}", "}}")

        if len(message) > 500:
            message = "Error occurred while connecting to the Splunk server"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        """
        Process json response.

        :param r: response object
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """
        status_code = r.status_code
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_UNABLE_TO_PARSE_JSON_RESPONSE.format(error=error_message)), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        if isinstance(resp_json, str):
            message = f"Error from server. Details: {resp_json}"
        elif resp_json.get("error") or resp_json.get("error_description"):
            error = resp_json.get("error", "Unavailable")
            error_details = resp_json.get("error_description", "Unavailable")
            message = f"Error from server. Status Code: {status_code}. Error: {error}. Error Details: {error_details}"
        elif resp_json.get("messages"):
            if resp_json["messages"]:
                error_type = resp_json["messages"][0].get("type")
                error_message = resp_json["messages"][0].get("text")

                if error_type or error_message:
                    error = f"ErrorType: {error_type} ErrorMessage: {error_message}"
                else:
                    error = "Unable to parse json response"
            else:
                error = "Unable to parse json response"

            message = f"Error from server. Status Code: {r.status_code} Data from server: {error}"
        else:
            # You should process the error returned in the json
            error_text = r.text.replace("{", "{{").replace("}", "}}")
            message = f"Error from server. Status Code: {status_code}. Data from server: {error_text}"

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _get_server_version(self, action_result):
        endpoint = "authentication/users?output_mode=json"
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, {}, method=requests.get)

        if phantom.is_fail(ret_val):
            return "FAILURE"

        splunk_version = resp_data.get("generator", {}).get("version")

        if not splunk_version:
            splunk_version = "UNKNOWN"

        return splunk_version

    def _check_for_es(self, action_result):
        endpoint = "apps/local/SplunkEnterpriseSecuritySuite"
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, {}, method=requests.get)
        if phantom.is_fail(ret_val) or not resp_data:
            return False
        return True

    def _resolve_event_id(self, sidandrid, action_result, kwargs_create=dict()):
        """Query the splunk instance using the SID+RID of the notable to find the notable ID"""

        self.send_progress(f"Running search_query: {consts.SPLUNK_RID_SID_NOTABLE_QUERY}")

        result = self._return_first_row_from_query(consts.SPLUNK_RID_SID_NOTABLE_QUERY.format(sidandrid), action_result)

        if phantom.is_fail(result):
            return RetVal(action_result.get_status(), None)

        if "event_id" in result:
            return RetVal(phantom.APP_SUCCESS, result["event_id"])

        return RetVal(action_result.set_status(phantom.APP_ERROR, "could not find event_id of splunk event"), None)

    def _return_first_row_from_query(self, search_query, action_result, kwargs_create=dict()):
        """Function that executes the query on splunk"""

        self.debug_print("Search Query:", search_query)
        RETRY_LIMIT = self.retry_count

        if phantom.is_fail(self._connect(action_result)):
            return action_result.get_status()

        # Validate the search query
        for attempt_count in range(0, RETRY_LIMIT):
            try:
                self._service.parse(search_query, parse_only=True)
                break
            except HTTPError as e:
                error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                    msg=consts.SPLUNK_ERR_INVALID_QUERY, error_text=self._get_error_message_from_exception(e)
                )
                return action_result.set_status(phantom.APP_ERROR, error_text, query=search_query)
            except Exception as e:
                if attempt_count == RETRY_LIMIT - 1:
                    error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                        msg=consts.SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=self._get_error_message_from_exception(e)
                    )
                    return action_result.set_status(phantom.APP_ERROR, error_text)

        self.debug_print(consts.SPLUNK_PROG_CREATED_QUERY.format(query=search_query))

        # Creating search job
        self.save_progress(consts.SPLUNK_PROG_CREATING_SEARCH_JOB)

        # Set any search creation flags here
        kwargs_create.update({"exec_mode": "normal"})

        self.debug_print("kwargs_create", kwargs_create)

        # Create the job
        for search_attempt_count in range(0, RETRY_LIMIT):
            # Create the job
            is_created_successfully, job = self._create_splunk_job(
                action_result=action_result, retry_limit=RETRY_LIMIT, search_query=search_query, kwargs_create=kwargs_create
            )
            if phantom.is_fail(is_created_successfully):
                return phantom.APP_ERROR

            while True:
                is_job_successful: bool = self._wait_until_splunk_job_results_are_ready(action_result, job, RETRY_LIMIT)
                if phantom.is_fail(is_job_successful):
                    return phantom.APP_ERROR

                stats = self._get_stats(job)

                status = ("Progress: %(progress)03.1f%%   %(scan_count)d scanned   %(event_count)d matched   %(result_count)d results") % stats  # noqa: UP031
                self.send_progress(status)
                if stats["is_done"] == "1":
                    break
                time.sleep(self.sleeptime_in_requests)
            self.send_progress("Parsing results...")

            try:
                results = splunk_results.JSONResultsReader(job.results(count=0, output_mode="json"))
            except Exception as e:
                error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                    msg="Error retrieving results", error_text=self._get_error_message_from_exception(e)
                )
                return action_result.set_status(phantom.APP_ERROR, error_text)

            for result in results:
                if isinstance(result, dict):
                    return result
            time.sleep(20)

        return action_result.set_status(phantom.APP_ERROR)

    def _post_data(self, param):
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        host = param.get(consts.SPLUNK_JSON_HOST)
        index = param.get(consts.SPLUNK_JSON_INDEX)
        source = param.get(consts.SPLUNK_JSON_SOURCE, consts.SPLUNK_DEFAULT_SOURCE)
        source_type = param.get(consts.SPLUNK_JSON_SOURCE_TYPE, consts.SPLUNK_DEFAULT_SOURCE_TYPE)
        try:
            post_data = UnicodeDammit(param[consts.SPLUNK_JSON_DATA]).unicode_markup.encode("utf-8")
        except Exception as e:
            self._dump_error_log(e, "Error while encoding data.")

        get_params = {"source": source, "sourcetype": source_type}

        if host:
            get_params["host"] = host
        if index:
            get_params["index"] = index

        endpoint = "receivers/simple"
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, post_data, params=get_params)

        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully posted the data")

    def _get_stats(self, job):
        stats = {
            "is_done": job["isDone"] if ("isDone" in job) else "Unknown status",
            "progress": (
                float(job["doneProgress"]) * 100
                if ("doneProgress" in job)
                else consts.SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Done progress")
            ),
            "scan_count": (
                int(job["scanCount"]) if ("scanCount" in job) else consts.SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Scan count")
            ),
            "event_count": (
                int(job["eventCount"]) if ("eventCount" in job) else consts.SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Event count")
            ),
            "result_count": (
                int(job["resultCount"]) if ("resultCount" in job) else consts.SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE.format(field="Result count")
            ),
        }

        return stats

    def _set_splunk_status_dict(self, action_result, type):
        splunk_dict = {}

        endpoint = "alerts/reviewstatuses?count=-1&output_mode=json"
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, {}, method=requests.get)

        if phantom.is_fail(ret_val) or not resp_data:
            return splunk_dict

        entry = resp_data.get("entry")

        if not entry:
            return splunk_dict

        for data in entry:
            object_id = data.get("name").split(":")[-1]
            object_name = data.get("content", {}).get("label")
            is_enabled = str(data.get("content", {}).get("disabled")) == "0"
            is_allowed_type = data.get("content", {}).get("status_type") == type
            if object_id and object_id.isdigit() and object_name and is_enabled and is_allowed_type:
                if type == "notable":
                    object_name = object_name.lower()
                splunk_dict[object_name] = int(object_id)

        return splunk_dict

    def _update_event(self, param):
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._check_for_es(action_result):
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_ES)

        owner = param.get(consts.SPLUNK_JSON_OWNER)
        ids = param.get(consts.SPLUNK_JSON_EVENT_IDS)
        status = param.get(consts.SPLUNK_JSON_STATUS)

        ret_val, integer_status = self._validate_integer(
            action_result, param.get("integer_status"), consts.SPLUNK_INT_STATUS_KEY, allow_zero=True
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, integer_disposition = self._validate_integer(
            action_result, param.get("integer_disposition"), consts.SPLUNK_INT_DISPOSITION_KEY, allow_zero=True
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        comment = param.get(consts.SPLUNK_JSON_COMMENT)
        urgency = param.get(consts.SPLUNK_JSON_URGENCY)
        wait_for_confirmation = param.get("wait_for_confirmation", False)
        disposition = param.get("disposition", "")
        regexp = re.compile(r"\+\d*(\.\d+)?[\"$]")
        if regexp.search(json.dumps(ids)):
            self.send_progress("Interpreting the event ID as an SID + RID combo; querying for the actual event_id...")
            self.debug_print("Interpreting the event ID as an SID + RID combo; querying for the actual event_id...")
            ret_val, event_id = self._resolve_event_id(ids, action_result, param)
            if phantom.is_fail(ret_val):
                return action_result.set_status(phantom.APP_ERROR, "Unable to find underlying event_id from SID + RID combo")
            ids = event_id

        if not any([comment, status, urgency, owner, disposition]) and integer_status is None and integer_disposition is None:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NEED_PARAM)

        if status or integer_status is not None:
            self._splunk_status_dict = self._set_splunk_status_dict(action_result, "notable")
            if not self._splunk_status_dict:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching Splunk event status")

        if disposition or integer_disposition is not None:
            self._splunk_disposition_dict = self._set_splunk_status_dict(action_result, "disposition")
            if not self._splunk_disposition_dict:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while fetching Splunk event disposition")

        self.debug_print("Attempting to create a connection")

        # 1. Connect and validate whether the given Event IDs are valid or not
        if phantom.is_fail(self._connect(action_result)):
            return action_result.get_status()

        self.debug_print("Connection established.")

        if wait_for_confirmation:
            self.debug_print("Searching for the event ID.")
            search_query = f"search `notable_by_id({ids})`"
            ret_val = self._run_query(search_query, action_result)

            if phantom.is_fail(ret_val):
                return action_result.set_status(
                    phantom.APP_ERROR, f"Error occurred while validating the provided event ID. Error: {action_result.get_message()}"
                )

            if int(action_result.get_data_size()) <= 0:
                return action_result.set_status(phantom.APP_ERROR, "Please provide a valid event ID")

            self.debug_print("Event ID found")

        # 2. Re-initialize the action_result object for update event
        self.remove_action_result(action_result)
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        # 3. Update the provided Events ID
        request_body = {"ruleUIDs": ids}

        if integer_status is not None:
            if int(integer_status) not in list(self._splunk_status_dict.values()):
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Please provide a valid value in 'integer_status' action\
                     parameter. Valid values: {}".format(", ".join(map(str, list(self._splunk_status_dict.values())))),
                )
            request_body["status"] = str(integer_status)
        elif status:
            if status not in self._splunk_status_dict:
                if not status.isdigit():
                    return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_BAD_STATUS)
                request_body["status"] = status
            else:
                request_body["status"] = self._splunk_status_dict[status]

        if integer_disposition is not None:
            if int(integer_disposition) not in self._splunk_disposition_dict.values():
                self.debug_print(f"int disposition: {self._splunk_disposition_dict}")
                return action_result.set_status(
                    phantom.APP_ERROR,
                    "Please provide a valid value in 'integer_disposition' action\
                     parameter. Valid values: {}".format(", ".join(map(str, self._splunk_disposition_dict.values()))),
                )
            request_body["disposition"] = consts.SPLUNK_DISPOSITION_QUERY_FORMAT.format(integer_disposition)
        elif disposition:
            if disposition not in self._splunk_disposition_dict:
                if not disposition.isdigit():
                    return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_BAD_DISPOSITION)
                request_body["disposition"] = consts.SPLUNK_DISPOSITION_QUERY_FORMAT.format(disposition)
            else:
                request_body["disposition"] = consts.SPLUNK_DISPOSITION_QUERY_FORMAT.format(self._splunk_disposition_dict[disposition])

        param_mapping = {"urgency": urgency, "comment": comment, "newOwner": owner}

        request_body.update({k: v for k, v in param_mapping.items() if v})

        self.debug_print("Updating the event")

        endpoint = "notable_update"
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, request_body)

        if not ret_val:
            return ret_val

        if "success" in resp_data and not resp_data.get("success"):
            msg = resp_data.get("message")
            return action_result.set_status(phantom.APP_ERROR, msg if msg else "Unable to update the notable event")

        action_result.add_data(resp_data)
        action_result.update_summary({consts.SPLUNK_JSON_UPDATED_EVENT_ID: ids})
        if wait_for_confirmation:
            return action_result.set_status(phantom.APP_SUCCESS)
        return action_result.set_status(
            phantom.APP_SUCCESS,
            f"Updated Event ID: {ids}. The event_id has not been verified. \
            Please confirm that the provided event_id corresponds to an actual notable event",
        )

    def _get_host_events(self, param):
        """Executes the query to get events pertaining to a host
        Gets the events for a host for the last 'N' number of days
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        # Connect
        if phantom.is_fail(self._connect(action_result)):
            return action_result.get_status()

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]

        # Validate last_n_days
        ret_val, last_n_days = self._validate_integer(action_result, param.get(consts.SPLUNK_JSON_LAST_N_DAYS), consts.SPLUNK_LAST_N_DAYS_KEY)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        search_query = 'search host="{}"{}'.format(ip_hostname, f" earliest=-{last_n_days}d" if last_n_days else "")

        self.debug_print(f"search_query: {search_query}")
        return self._run_query(search_query, action_result)

    def _get_fips_enabled(self):
        try:
            from phantom_common.install_info import is_fips_enabled
        except ImportError:
            return False

        fips_enabled = is_fips_enabled()
        if fips_enabled:
            self.debug_print("FIPS is enabled")
        else:
            self.debug_print("FIPS is not enabled")
        return fips_enabled

    def _on_poll(self, param):
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if phantom.is_fail(self._connect(action_result)):
            return action_result.get_status()

        config = self.get_config()
        search_command = config.get("on_poll_command")
        search_string = config.get("on_poll_query")
        po = config.get("on_poll_parse_only", False)
        include_cim_fields = config.get("include_cim_fields", False)
        use_event_id_sdi = config.get("use_event_id_sdi", False)

        if not search_string:
            self.save_progress("Need to specify Query String to use polling")
            return action_result.set_status(phantom.APP_ERROR)

        try:
            if not search_command:
                if (search_string[0] != "|") and (search_string.find("search", 0) != 0):
                    search_string = f"search {search_string.strip()}"
                search_query = search_string
            else:
                search_query = f"{search_command.strip()} {search_string.strip()}"
        except Exception:
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while parsing the search query")

        search_params = {}

        if self.is_poll_now():
            search_params["max_count"] = param.get("container_count", 100)
        else:
            search_params["max_count"] = self.max_container
            start_time = self._state.get("start_time")
            if start_time:
                search_params["index_earliest"] = start_time

        if int(search_params["max_count"]) <= 0:
            self.debug_print(
                "The value of 'container_count' parameter must be a positive integer. \
            The value provided in the 'container_count' parameter is {}.\
            Therefore, 'container_count' parameter will be ignored".format(int(search_params["max_count"]))
            )
            search_params.pop("max_count")

        ret_val = self._run_query(search_query, action_result, kwargs_create=search_params, parse_only=po)
        if phantom.is_fail(ret_val):
            if "Invalid index_earliest" in action_result.get_message():
                self.debug_print(
                    "The value of 'start_time' parameter {} is not a valid epoch time. Re-invoking api without start_time".format(
                        search_params.get("index_earliest")
                    )
                )
                del self._state["start_time"]
            else:
                self.save_progress(action_result.get_message())
            return action_result.set_status(phantom.APP_ERROR)

        display = config.get("on_poll_display")
        header_set = None
        if display:
            header_set = [x.strip().lower() for x in display.split(",")]

        # Set the most recent event to data[0]
        data = list(reversed(action_result.get_data()))
        self.save_progress("Finished search")

        self.debug_print(f"Total {len(data)} event(s) fetched")

        count = 1

        for item in data:
            container = {}
            cef = {}
            if "_serial" in item:
                item.pop("_serial")
            if header_set:
                name_mappings = {}
                for k, v in list(item.items()):
                    if k.lower() in header_set:
                        # Use this to keep the orignal capitalization from splunk
                        name_mappings[k.lower()] = k
                for h in header_set:
                    cef_name = consts.CIM_CEF_MAP.get(h, h)
                    cef_name = name_mappings.get(cef_name, cef_name)
                    cef_key_value = name_mappings.get(h, h)
                    cef[cef_name] = item.get(cef_key_value)
                    # Add original CIM fields if option is checked
                    cef.update({cef_key_value: item.get(cef_key_value)} if include_cim_fields else {})
            else:
                for k, v in list(item.items()):
                    cef[consts.CIM_CEF_MAP.get(k, k)] = v
                    # Add original CIM fields if option is checked
                    cef.update({k: v} if include_cim_fields else {})

            # If the boolean in the asset is checked, attempt to use event_id as the source data identifier
            # If event_id is missing from event, print warning and use hash SDI
            if use_event_id_sdi and "event_id" in item:
                sdi = item["event_id"]
            else:
                if use_event_id_sdi and "event_id" not in item:
                    self.save_progress("Use event_id as SDI is activated in the asset but event_id is missing from this event.")
                    self.save_progress("Defaulting to event hash")
                input_str = json.dumps(item)
                input_str = UnicodeDammit(input_str).unicode_markup.encode("utf-8")
                fips_enabled = self._get_fips_enabled()
                # if fips is not enabled, we should continue with our existing md5 usage for generating SDIs
                # to not impact existing customers
                if not fips_enabled:
                    sdi = hashlib.md5(input_str).hexdigest()  # nosemgrep
                else:
                    sdi = hashlib.sha256(input_str).hexdigest()

            severity = self._get_splunk_severity(item)
            spl_event_start = self._get_event_start(item.get("_time"))

            container["name"] = self._get_splunk_title(item)
            container["severity"] = severity
            container["source_data_identifier"] = sdi

            ret_val, msg, cid = self.save_container(container)
            if phantom.is_fail(ret_val):
                self.save_progress(f"Error saving container: {msg}")
                self.debug_print(f"Error saving container: {msg} -- CID: {cid}")
                continue

            if self.remove_empty_cef:
                cleaned_cef = {}
                for key, value in list(cef.items()):
                    if value is not None:
                        cleaned_cef[key] = value
                cef = cleaned_cef
            artifact = [
                {
                    "cef": cef,
                    "name": "Field Values",
                    "source_data_identifier": sdi,
                    "severity": severity,
                    "start_time": spl_event_start,
                    "container_id": cid,
                }
            ]
            create_artifact_status, create_artifact_msg, _ = self.save_artifacts(artifact)
            if phantom.is_fail(create_artifact_status):
                self.save_progress(f"Error saving artifact: {create_artifact_msg}")
                self.debug_print(f"Error saving artifact: {create_artifact_msg}")
                continue

            if count == self.container_update_state and not self.is_poll_now():
                self._state["start_time"] = item.get("_indextime")
                self.save_state(self._state)
                self.debug_print("Index time updated")
                count = 0

            count += 1

        if data and not self.is_poll_now():
            self._state["start_time"] = data[-1].get("_indextime")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_event_start(self, start_time):
        # use platform default start_time
        if not start_time:
            return None

        try:
            # convert to Splunk SOAR timestamp format
            # '%Y-%m-%dT%H:%M:%S.%fZ
            datetime_obj = dateutil_parse(start_time)
            return datetime_obj.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ParserError as parse_err:
            self._dump_error_log(parse_err, "ParserError while parsing _time.")
            error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                msg="ParserError while parsing _time", error_text=self._get_error_message_from_exception(parse_err)
            )
            self.save_progress(error_text)
            return None
        except Exception as e:
            self._dump_error_log(e, "Exception while parsing _time.")
            error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                msg="Exception while parsing _time", error_text=self._get_error_message_from_exception(e)
            )
            self.save_progress(error_text)
            return None

    def _get_splunk_title(self, item):
        title = self._container_name_prefix
        if not title and not self._container_name_values:
            self._container_name_values.append("source")
        values = ""
        for i in range(len(self._container_name_values)):
            if consts.CIM_CEF_MAP.get(self._container_name_values[i]) and item.get(consts.CIM_CEF_MAP.get(self._container_name_values[i])):
                value = item.get(consts.CIM_CEF_MAP.get(self._container_name_values[i]))
            elif item.get(self._container_name_values[i]):
                value = item.get(self._container_name_values[i])
            else:
                value = consts.CIM_CEF_MAP.get(self._container_name_values[i], self._container_name_values[i])
            values += "{}{}".format(value, "" if i == len(self._container_name_values) - 1 else ", ")

        if not title:
            time = item.get("_time")
            if time:
                title = f"Splunk Log Entry on {time}"
            else:
                title = "Splunk Log Entry"
        else:
            title = item.get(title, title)

        return f"{title}: {values}"

    def _get_splunk_severity(self, item):
        severity = item.get("severity")
        if isinstance(severity, list):
            severity_keys = ["critical", "high", "medium", "low", "informational"]
            for severity_key in severity_keys:
                if severity_key in severity:
                    severity = consts.SPLUNK_SEVERITY_MAP[severity_key]
                    break
            else:
                severity = ""
        else:
            severity = consts.SPLUNK_SEVERITY_MAP.get(severity)

        if not severity:
            # Check to see if urgency is set
            urgency = item.get("urgency")
            severity = consts.SPLUNK_SEVERITY_MAP.get(urgency, "medium")
        return severity

    def _handle_run_query(self, param):
        """Perform Splunk run query

        How we run Splunk search: https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtorunsearchespython/ # noqa
        Raw REST endpoint: https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs
        Time modifiers: https://docs.splunk.com/Documentation/Splunk/8.2.5/SearchReference/SearchTimeModifiers
        """
        self.save_progress(f"In action handler for: {self.get_action_identifier()}")
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        # Connect
        if phantom.is_fail(self._connect(action_result)):
            return action_result.get_status()

        search_command = param.get(consts.SPLUNK_JSON_COMMAND)
        search_string = param.get(consts.SPLUNK_JSON_QUERY)
        po = param.get(consts.SPLUNK_JSON_PARSE_ONLY, False)
        attach_result = param.get(consts.SPLUNK_JSON_ATTACH_RESULT, False)
        search_mode = param.get(consts.SPLUNK_JSON_SEARCH_MODE, consts.SPLUNK_SEARCH_MODE_SMART)
        add_raw = param.get(consts.SPLUNK_JSON_ADD_RAW_DATA)

        # More info on valid time modifier at https://docs.splunk.com/Documentation/Splunk/8.2.5/SearchReference/SearchTimeModifiers
        start_time = phantom.get_value(param, consts.SPLUNK_JSON_START_TIME)
        end_time = phantom.get_value(param, consts.SPLUNK_JSON_END_TIME)
        self.debug_print(f"Run query with timeframe ({start_time}, {end_time})")
        kwargs = {}
        if start_time:
            kwargs["earliest_time"] = start_time
        if end_time:
            kwargs["latest_time"] = end_time

        kwargs["adhoc_search_level"] = search_mode

        try:
            if not search_command:
                if (search_string[0] != "|") and (search_string.find("search", 0) != 0):
                    search_string = f"search {search_string.strip()}"
                search_query = search_string
            else:
                search_query = f"{search_command.strip()} {search_string.strip()}"
        except Exception as e:
            self._dump_error_log(e)
            return action_result.set_status(phantom.APP_ERROR, "Error occurred while parsing the search query")

        self.debug_print(f"search_query: {search_query}")
        return self._run_query(
            search_query, action_result, attach_result=attach_result, kwargs_create=kwargs, parse_only=po, add_raw_field=add_raw
        )

    def _get_tz_str_from_epoch(self, time_format_str, epoch_milli):
        # Need to convert from UTC to the device's timezone, get the device's tz from config
        config = self.get_config()
        device_tz_sting = config[consts.SPLUNK_JSON_TIMEZONE]

        to_tz = ZoneInfo(device_tz_sting)

        utc_dt = datetime.fromtimestamp(epoch_milli // 1000, tz=timezone.utc)
        to_dt = utc_dt.astimezone(to_tz)

        # return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
        return to_dt.strftime(time_format_str)

    def _list_alerts(self, param, action_result=None):
        if not action_result:
            # Create a action result to represent this action
            action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        # If end_time is not given, then end_time is 'now'
        # If start_time is not given, then start_time is SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME
        # days behind end_time
        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(phantom.get_value(param, consts.SPLUNK_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = int(
            phantom.get_value(
                param,
                consts.SPLUNK_JSON_START_TIME,
                end_time_msecs - (consts.SPLUNK_MILLISECONDS_IN_A_DAY * consts.SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME),
            )
        )

        if end_time_msecs < start_time_msecs:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_TIME_RANGE)

        # From splunk documentation
        # To search with an exact date as boundary, such as from November 5 at 8 PM to November 12 at 8 PM,
        # use the timeformat: %m/%d/%Y:%H:%M:%S
        # TODO, We need not convert the epoch to formatted and then pass the format string also to splunk
        # We should be able to work off of just epoch, however not too sure what the input epoch UTC format
        # is to splunk and the doc is not that clear.
        time_format_str = "%m/%d/%Y:%H:%M:%S"
        earliest_time = f"{self._get_tz_str_from_epoch(time_format_str, start_time_msecs)}"
        latest_time = f"{self._get_tz_str_from_epoch(time_format_str, end_time_msecs)}"

        kwargs_create = {"earliest_time": earliest_time, "latest_time": latest_time, "time_format": time_format_str}
        # kwargs_create = {"time_format": "%m/%d/%Y:%H:%M:%S",
        #         "latest_time": "03/21/2015:14:29:25",
        #         "earliest_time": "03/21/2015:14:24:25"}

        self.save_progress(consts.SPLUNK_PROG_TIME_RANGE, range=json.dumps(kwargs_create))

        count = int(phantom.get_value(param, phantom.APP_JSON_CONTAINER_COUNT, consts.SPLUNK_DEFAULT_ALERT_COUNT))

        # Work of the saved search name, if given
        ss_name = phantom.get_value(self.get_config(), consts.SPLUNK_JSON_ALERT_NAME, None)

        # default to blank
        ss_query = ""

        if ss_name:
            # create a list of query's is easier then just replacing the ',' with 'OR ss_name=
            #  that way we can work on each one of them seperately, like strip them or add quotes
            #  if not present etc.
            ss_names = ['"{}"'.format(x.strip(' "')) for x in ss_name.split(",") if len(x.strip()) > 0]
            self.debug_print("ss_names", ss_names)
            ss_query = "ss_name = {}".format(" OR ss_name = ".join(ss_names))

        query = consts.SPLUNK_SEARCH_AUDIT_INDEX_QUERY.format(ss_query, count)

        self.debug_print("query", query)

        self._run_query(query, action_result, kwargs_create=kwargs_create)

        return action_result.get_status()

    def _test_asset_connectivity(self, param):
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if phantom.is_fail(self._connect(action_result)):
            self.debug_print("connect failed")
            self.save_progress(consts.SPLUNK_ERR_CONNECTIVITY_TEST)
            return action_result.append_to_message(consts.SPLUNK_ERR_CONNECTIVITY_TEST)

        version = self._get_server_version(action_result)
        if version == "FAILURE":
            return action_result.append_to_message(consts.SPLUNK_ERR_CONNECTIVITY_TEST)

        is_es = self._check_for_es(action_result)

        self.save_progress("Detected Splunk {}server version {}".format("ES " if is_es else "", version))

        self.debug_print("connect passed")
        self.save_progress(consts.SPLUNK_SUCCESS_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS, consts.SPLUNK_SUCCESS_CONNECTIVITY_TEST)

    def _run_query(self, search_query, action_result, attach_result=False, kwargs_create=dict(), parse_only=True, add_raw_field=True):
        """Function that executes the query on splunk"""
        self.debug_print("Start run query")
        RETRY_LIMIT = self.retry_count
        summary = action_result.update_summary({})
        summary["sid"] = "Search ID not created"

        # Validate the search query
        for attempt_count in range(0, RETRY_LIMIT):
            try:
                self._service.parse(search_query, parse_only=parse_only)
                break
            except HTTPError as e:
                self._dump_error_log(e, "Failed to validate search query.")
                if phantom.is_fail(self._connect(action_result)):
                    return action_result.get_status()
                if attempt_count == RETRY_LIMIT - 1:
                    error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                        msg=consts.SPLUNK_ERR_INVALID_QUERY, error_text=self._get_error_message_from_exception(e)
                    )
                    return action_result.set_status(phantom.APP_ERROR, error_text, query=search_query)
            except Exception as e:
                self._dump_error_log(e, "Failed to validate search query.")
                if phantom.is_fail(self._connect(action_result)):
                    return action_result.get_status()
                if attempt_count == RETRY_LIMIT - 1:
                    error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                        msg=consts.SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=self._get_error_message_from_exception(e)
                    )
                    return action_result.set_status(phantom.APP_ERROR, error_text)

        self.debug_print(consts.SPLUNK_PROG_CREATED_QUERY.format(query=search_query))

        # Creating search job
        self.save_progress(consts.SPLUNK_PROG_CREATING_SEARCH_JOB)

        # Set any search creation flags here
        kwargs_create.update({"exec_mode": "normal"})

        self.debug_print("kwargs_create", kwargs_create)

        # Create the job
        is_created_successfully, job = self._create_splunk_job(
            action_result=action_result, retry_limit=RETRY_LIMIT, search_query=search_query, kwargs_create=kwargs_create
        )
        if phantom.is_fail(is_created_successfully):
            return phantom.APP_ERROR

        summary["sid"] = job.__dict__.get("sid")

        result_count = 0
        while True:
            is_job_successful: bool = self._wait_until_splunk_job_results_are_ready(action_result, job, RETRY_LIMIT)
            if phantom.is_fail(is_job_successful):
                return phantom.APP_ERROR

            stats = self._get_stats(job)

            if not ("doneProgress" in job and "scanCount" in job and "eventCount" in job and "resultCount" in job):
                status = "Progress: {}   {} scanned   {} matched   {} results".format(
                    stats.get("progress"), stats.get("scan_count"), stats.get("event_count"), stats.get("result_count")
                )
            else:
                status = ("Progress: %(progress)03.1f%%   %(scan_count)d scanned   %(event_count)d matched   %(result_count)d results") % stats  # noqa: UP031
            self.send_progress(status)
            if stats["is_done"] == "1":
                result_count = stats["result_count"]
                break
            time.sleep(self.sleeptime_in_requests)

        self.send_progress("Parsing results...")
        result_index = 0
        ten_percent = float(result_count) * 0.10

        try:
            results = splunk_results.JSONResultsReader(job.results(count=kwargs_create.get("max_count", 0), output_mode="json"))
        except Exception as e:
            self._dump_error_log(e)
            error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                msg="Error retrieving results", error_text=self._get_error_message_from_exception(e)
            )
            return action_result.set_status(phantom.APP_ERROR, error_text)

        for result in results:
            if not isinstance(result, dict):
                continue

            if not add_raw_field:
                result.pop("_raw", None)

            action_result.add_data(result)

            result_index += 1

            if (result_index % ten_percent) == 0:
                status = f"Finished parsing {float(result_index) / float(result_count):.1%} of results"
                self.send_progress(status)

        if attach_result:
            self.add_json_result(action_result)

        summary[consts.SPLUNK_JSON_TOTAL_EVENTS] = result_index
        self.debug_print("Done run query")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _wait_until_splunk_job_results_are_ready(self, action_result: phantom.ActionResult, job: splunk_client.Job, retry_limit: int) -> bool:
        for attempt_count in range(1, retry_limit + 1):
            max_waiting_time: float = time.time() + self.splunk_job_timeout
            try:
                #  Timing out the splunk job is required, because the job
                #  could be stuck in permanent "QUEUED" state after the Splunk
                #  stack has crashed.
                while not job.is_ready():
                    if time.time() > max_waiting_time:
                        return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_SPLUNK_JOB_HAS_TIMED_OUT)
                    time.sleep(self.sleeptime_in_requests)
                job.refresh()
                break
            except Exception as e:
                self.debug_print(f"Attempt {attempt_count} out of {retry_limit} to connect to splunk server failed with error: {e}.")
                if attempt_count == retry_limit:
                    error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                        msg=consts.SPLUNK_ERR_CONNECTIVITY_FAILED, error_text=self._get_error_message_from_exception(e)
                    )
                    return action_result.set_status(phantom.APP_ERROR, error_text)
        return True

    def _create_splunk_job(
        self, action_result: phantom.ActionResult, retry_limit: int, search_query: str, kwargs_create: dict
    ) -> tuple[bool, Optional[splunk_client.Job]]:
        for attempt_count in range(1, retry_limit + 1):
            try:
                job: splunk_client.Job = self._service.jobs.create(search_query, **kwargs_create)
                break
            except Exception as e:
                self.debug_print(f"Attempt {attempt_count} out of {retry_limit} to create splunk job failed with error: {e}.")
                self._dump_error_log(e, "Failed to create job.")
                if attempt_count == retry_limit:
                    error_text = consts.SPLUNK_EXCEPTION_ERR_MESSAGE.format(
                        msg=consts.SPLUNK_ERR_UNABLE_TO_CREATE_JOB, error_text=self._get_error_message_from_exception(e)
                    )
                    return action_result.set_status(phantom.APP_ERROR, error_text), None
        return True, job

    def add_json_result(self, action_result):
        fd, path = tempfile.mkstemp(dir=Vault.get_vault_tmp_dir(), text=True)
        vault_attach_dict = {}

        vault_attach_dict[phantom.APP_JSON_ACTION_NAME] = self.get_action_name()
        vault_attach_dict[phantom.APP_JSON_APP_RUN_ID] = self.get_app_run_id()

        try:
            with open(path, "w") as f:
                json.dump(action_result.get_data(), f)

        except Exception as e:
            self._dump_error_log(e, "Error occurred while adding file to Vault.")
            error_message = self._get_error_message_from_exception(e)
            msg = f"Error occurred while adding file to Vault. Error Details: {error_message}"
            self.debug_print(msg)
            return phantom.APP_ERROR

        container_id = self.get_container_id()

        try:
            success, message, _ = soar_vault.vault_add(container_id, path, "splunk_run_query_result.json", vault_attach_dict)

        except Exception as e:
            self._dump_error_log(e)
            err = self._get_error_message_from_exception(e)
            self.debug_print(phantom.APP_ERR_FILE_ADD_TO_VAULT.format(err))
            return action_result.set_status(phantom.APP_ERROR, phantom.APP_ERR_FILE_ADD_TO_VAULT.format(err))

        if not success:
            err = f"Failed to add file to Vault: {message}"
            self.debug_print(err)
            return action_result.set_status(phantom.APP_ERROR, err)

    def handle_action(self, param):
        """Function that handles all the actions
        Args:
            The json containing config, action and supporting parameters
            Handle to the ph_connector, should be used/passed when making ph_connector function calls
        Return:
            status code
        """

        # Get the action that we are supposed to carry out, set it in the connection result object
        action = self.get_action_identifier()
        self.send_progress(f"executing action: {action}")
        if action == self.ACTION_ID_RUN_QUERY:
            result = self._handle_run_query(param)
        elif action == self.ACTION_ID_POST_DATA:
            result = self._post_data(param)
        elif action == self.ACTION_ID_UPDATE_EVENT:
            result = self._update_event(param)
        elif action == self.ACTION_ID_GET_HOST_EVENTS:
            result = self._get_host_events(param)
        elif action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY:
            result = self._test_asset_connectivity(param)
        elif action == "on_poll":
            result = self._on_poll(param)

        return result


if __name__ == "__main__":
    import argparse

    import pudb
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        login_url = BaseConnector._get_phantom_base_url() + "login"
        try:
            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify, timeout=consts.SPLUNK_DEFAULT_REQUEST_TIMEOUT)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers, timeout=consts.SPLUNK_DEFAULT_REQUEST_TIMEOUT)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit(1)

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SplunkConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
