# File: splunk_consts.py
#
# Copyright (c) 2016-2022 Splunk Inc.
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
#
# Success/Error status and messages
SPLUNK_ERR_INVALID_QUERY = "Query invalid '{query}'"
SPLUNK_SUCC_QUERY_EXECUTED = "Executed splunk query"
SPLUNK_ERR_BAD_STATUS = "The supplied status is invalid"
SPLUNK_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
SPLUNK_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
SPLUNK_ERR_NOT_JSON = "Splunk server response was not JSON"
SPLUNK_ERR_NOT_200 = "Splunk server returned error from API call"
SPLUNK_ERR_CONNECTION_FAILED = "Failed to connect to splunk server"
SPLUNK_ERR_UNABLE_TO_CREATE_JOB = "Failed to get a job id from splunk server"
SPLUNK_ERR_GET_EVENTS = "Error getting events for alert '{ss_name}' having sid '{sid}'"
SPLUNK_ERR_NOT_ES = "This instance does not seem to be Splunk ES. This action cannot be run"
SPLUNK_ERR_CONNECTION_NOT_PRE_ESTABLISHED = "Connection to splunk server not yet established"
SPLUNK_ERR_INVALID_TIME_RANGE = "Invalid Time range specified, where the end time is less than start time"
SPLUNK_ERR_NEED_PARAM = "One of comment, status, integer_status, urgency, or owner parameters needs to be supplied to run this \
    action"
SPLUNK_ERR_INVALID_INTEGER = "Please provide a valid integer value in the {param} parameter"
SPLUNK_ERR_NON_NEGATIVE_INTEGER = "Please provide a valid non-negative integer value in the {param} parameter"
SPLUNK_ERR_INVALID_PARAM = "Please provide non-zero positive integer in {param}"
SPLUNK_ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters."
SPLUNK_EXCEPTION_ERROR_MESSAGE = "{msg}. {error_text}"
SPLUNK_JOB_FIELD_NOT_FOUND_MESSAGE = "{field} not found"
SPLUNK_ERR_INVALID_SLEEP_TIME = "Please provide a value <= 120 seconds in the {param} parameter"
SPLUNK_ERR_REQUIRED_CONFIG_PARAMS = "Please provide either API token or username and password in the asset \
    configuration parameters for authentication"
SPLUNK_STATE_FILE_CORRUPT_ERR = (
    "Error occurred while loading the state file due to its unexpected format. "
    "Resetting the state file with the default format. Please try again."
)
SPLUNK_ERR_UNABLE_TO_PARSE_JSON_RESPONSE = "Unable to parse response as JSON. {error}"
SPLUNK_ERR_EMPTY_RESPONSE = "Status Code {code}. Empty response and no information in the header."

# Progress messages
SPLUNK_PROG_GOT_JOB_ID = "Got job id '{job_id}'"
SPLUNK_PROG_TIME_RANGE = "Using range '{range}'"
SPLUNK_PROG_CREATED_QUERY = "Created query '{query}'"
SPLUNK_PROG_CREATING_SEARCH_JOB = "Creating search job"
SPLUNK_PROG_WAITING_ON_JOB_ID = "Waiting for job (id:{job_id}) to finish"
SPLUNK_PROG_CHECKING_STATUS_OF_JOB_ID = "Checking status of job id '{job_id}'"
SPLUNK_PROG_JOB_ID_DONE_RETRIEVING_RESULTS = "Retrieving results for job id '{job_id}'"

# Json keys
SPLUNK_JSON_COMMAND = "command"
SPLUNK_JSON_PARSE_ONLY = "parse_only"
SPLUNK_JSON_HOST = "host"
SPLUNK_JSON_DATA = "data"
SPLUNK_JSON_INDEX = "index"
SPLUNK_JSON_QUERY = "query"
SPLUNK_JSON_COUNT = "count"
SPLUNK_JSON_OWNER = "owner"
SPLUNK_JSON_SOURCE = "source"
SPLUNK_JSON_STATUS = "status"
SPLUNK_JSON_URGENCY = "urgency"
SPLUNK_JSON_COMMENT = "comment"
SPLUNK_JSON_ALERT_NAME = "alert"
SPLUNK_JSON_END_TIME = "end_time"
SPLUNK_JSON_TIMEZONE = "timezone"
SPLUNK_JSON_EVENT_IDS = "event_ids"
SPLUNK_JSON_START_TIME = "start_time"
SPLUNK_JSON_SOURCE_TYPE = "source_type"
SPLUNK_JSON_LAST_N_DAYS = "last_n_days"
SPLUNK_JSON_TOTAL_EVENTS = "total_events"
SPLUNK_JSON_UPDATED_EVENT_ID = "updated_event_id"
SPLUNK_JSON_ATTACH_RESULT = "attach_result"
SPLUNK_JSON_API_KEY = "api_token"  # pragma: allowlist secret

# Default values
SPLUNK_DEFAULT_EVENT_COUNT = 10
SPLUNK_DEFAULT_ALERT_COUNT = 100
SPLUNK_DEFAULT_SOURCE = "Phantom"
SPLUNK_DEFAULT_SOURCE_TYPE = "Automation/Orchestration Platform"

# Numeric constants
SPLUNK_MILLISECONDS_IN_A_DAY = 86400000
SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME = 10

# Dictionaries
SPLUNK_SEVERITY_MAP = {
    'informational': 'low',
    'low': 'low',
    'medium': 'medium',
    'high': 'high',
    'critical': 'high'
}

# This will map certain splunk CIM fields to their CEF equivalent
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
    "user_id": "destinationUserId"
}

SPLUNK_INVALID_COMMAND = "Streaming/Transforming command operates on the events returned by some search.\
    So for using (eval, stats, table) commands, user should provide 'search' in 'command' parameter \
    and provide whole query in the 'query' parameter"

# Validation keys
SPLUNK_INT_STATUS_KEY = "'integer_status' action"
SPLUNK_RETRY_COUNT_KEY = "'retry_count' configuration"
SPLUNK_PORT_KEY = "'port' configuration"
SPLUNK_MAX_CONTAINER_KEY = "'max_container' configuration"
SPLUNK_CONTAINER_UPDATE_STATE_KEY = "'Container count to update the state file' configuration"
SPLUNK_LAST_N_DAYS_KEY = "'last_n_days' action"
SPLUNK_SLEEPTIME_IN_REQUESTS_KEY = "'The time to wait for next REST call (max 120 seconds)' configuration"

# Queries
SPLUNK_RID_SID_NOTABLE_QUERY = r'search [| makeresults | eval myfield = "{}"'
SPLUNK_RID_SID_NOTABLE_QUERY += r' | rex field=myfield "^(?<sid>.*)\+(?<rid>\d*(\.\d+)?)"'
SPLUNK_RID_SID_NOTABLE_QUERY += r' | eval search = "( (sid::" . sid . " OR orig_sid::" . sid . ")'
SPLUNK_RID_SID_NOTABLE_QUERY += r' (rid::" . rid . " OR orig_rid::" . rid . ") )"'
SPLUNK_RID_SID_NOTABLE_QUERY += r' | table search] `notable` | table event_id'
SPLUNK_SEARCH_AUDIT_INDEX_QUERY = "search index=_audit action=alert_fired {0} | head {1} | \
            fields ss_name sid trigger_time severity"

SPLUNK_DEFAULT_REQUEST_TIMEOUT = 60  # in seconds
