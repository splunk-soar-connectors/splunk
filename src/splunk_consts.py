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

# Success/Error messages
SPLUNK_ERR_INVALID_QUERY = "Query invalid '{query}'"
SPLUNK_ERR_BAD_STATUS = "The supplied status is invalid"
SPLUNK_ERR_BAD_DISPOSITION = "The supplied disposition is invalid"
SPLUNK_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
SPLUNK_SUCCESS_CONNECTIVITY_TEST = "Connectivity test passed"
SPLUNK_ERR_CONNECTIVITY_FAILED = "Failed to connect to splunk server"
SPLUNK_ERR_UNABLE_TO_CREATE_JOB = "Failed to get a job id from splunk server"
SPLUNK_ERR_NOT_ES = (
    "This instance does not seem to be Splunk ES. This action cannot be run"
)
SPLUNK_ERR_INVALID_TIME_RANGE = (
    "Invalid Time range specified, where the end time is less than start time"
)
SPLUNK_ERR_NEED_PARAM = (
    "One of comment, status, integer_status, disposition, integer_disposition, "
    "urgency, or owner parameters needs to be supplied to run this action"
)
SPLUNK_ERR_INVALID_INTEGER = (
    "Please provide a valid integer value in the {param} parameter"
)
SPLUNK_ERR_NON_NEGATIVE_INTEGER = (
    "Please provide a valid non-negative integer value in the {param} parameter"
)
SPLUNK_ERR_INVALID_PARAM = "Please provide non-zero positive integer in {param}"
SPLUNK_ERR_MESSAGE_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
SPLUNK_EXCEPTION_ERR_MESSAGE = "{msg}. {error_text}"
SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE = "{field} not found"
SPLUNK_ERR_INVALID_SLEEP_TIME = (
    "Please provide a value <= 120 seconds in the {param} parameter"
)
SPLUNK_ERR_REQUIRED_CONFIG_PARAMS = (
    "Please provide either API token or username and password in the asset "
    "configuration parameters for authentication"
)
SPLUNK_ERR_SPLUNK_JOB_HAS_TIMED_OUT = (
    "Failed to retrieve splunk job results. The splunk job has timed out."
)
SPLUNK_ERR_UNABLE_TO_PARSE_JSON_RESPONSE = "Unable to parse response as JSON. {error}"
SPLUNK_ERR_UNABLE_TO_PARSE_HTML_RESPONSE = "Unable to parse HTML response. {error}"
SPLUNK_ERR_EMPTY_RESPONSE = (
    "Status Code {code}. Empty response and no information in the header."
)

# Progress messages
SPLUNK_PROG_CREATED_QUERY = "Created query '{query}'"
SPLUNK_PROG_CREATING_SEARCH_JOB = "Creating search job"

# Default values
SPLUNK_DEFAULT_SOURCE = "Phantom"
SPLUNK_DEFAULT_SOURCE_TYPE = "Automation/Orchestration Platform"

# Numeric constants
SPLUNK_MILLISECONDS_IN_A_DAY = 86400000
SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME = 10

# Dictionaries
SPLUNK_SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "high",
}

CIM_CEF_MAP = {
    "action": "act",
    "action_name": "act",
    "app": "app",
    "bytes_in": "butesIn",
    "bytes_out": "bytesOut",
    "category": "cat",
    "dest": "destinationAddress",
    "dest_ip": "destinationAddress",
    "dest_mac": "destinationMacAddress",
    "dest_nt_domain": "destinationNtDomain",
    "dest_port": "destinationPort",
    "dest_translated_ip": "destinationTranlsatedAddress",
    "dest_translated_port": "destinationTranslatedPort",
    "direction": "deviceDirection",
    "dns": "destinationDnsDomain",
    "dvc": "dvc",
    "dvc_ip": "deviceAddress",
    "dvc_mac": "deviceMacAddress",
    "file_create_time": "fileCreateTime",
    "file_hash": "fileHash",
    "file_modify_time": "fileModificationTime",
    "file_name": "fileName",
    "file_path": "filePath",
    "file_size": "fileSize",
    "message": "message",
    "protocol": "transportProtocol",
    "request_payload": "request",
    "request_payload_type": "requestMethod",
    "src": "sourceAddress",
    "src_dns": "sourceDnsDomain",
    "src_ip": "sourceAddress",
    "src_mac": "sourceMacAddress",
    "src_nt_domain": "sourceNtDomain",
    "src_port": "sourcePort",
    "src_translated_ip": "sourceTranslatedAddress",
    "src_translated_port": "sourceTranslatedPort",
    "src_user": "sourceUserId",
    "transport": "transportProtocol",
    "url": "requestURL",
    "user": "destinationUserName",
    "user_id": "destinationUserId",
}

# Queries
SPLUNK_RID_SID_NOTABLE_QUERY = r'search [| makeresults | eval myfield = "{}"'
SPLUNK_RID_SID_NOTABLE_QUERY += (
    r' | rex field=myfield "^(?<sid>.*)\+(?<rid>\d*(\.\d+)?)"'
)
SPLUNK_RID_SID_NOTABLE_QUERY += (
    r' | eval search = "( (sid::" . sid . " OR orig_sid::" . sid . ")'
)
SPLUNK_RID_SID_NOTABLE_QUERY += r' (rid::" . rid . " OR orig_rid::" . rid . ") )"'
SPLUNK_RID_SID_NOTABLE_QUERY += r" | table search] `notable` | table event_id"

SPLUNK_DEFAULT_REQUEST_TIMEOUT = 60  # in seconds

# Search Modes
SPLUNK_SEARCH_MODE_SMART = "smart"

SPLUNK_DISPOSITION_QUERY_FORMAT = "disposition:{}"
