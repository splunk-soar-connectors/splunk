# --
# File: splunk_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

# Success/Error status and messages
SPLUNK_ERR_INVALID_QUERY = "Query invalid '{query}'"
SPLUNK_SUCC_QUERY_EXECUTED = "Executed splunk query"
SPLUNK_ERR_BAD_STATUS = "The supplied status is invalid"
SPLUNK_ERR_CONNECTIVITY_TEST = "Connectivity test failed"
SPLUNK_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
SPLUNK_ERR_NOT_JSON = "Splunk server response was not JSON"
SPLUNK_ERR_CONNECTION_FAILED = "Failed to connect to splunk server"
SPLUNK_ERR_UNABLE_TO_CREATE_JOB = "Failed to get a job id from splunk server"
SPLUNK_ERR_GET_EVENTS = "Error getting events for alert '{ss_name}' having sid '{sid}'"
SPLUNK_ERR_NOT_200 = "Splunk server return error from API call. Code: {0}. Message: {1}"
SPLUNK_ERR_NOT_ES = "This instance does not seem to be Splunk ES. This action cannot be run"
SPLUNK_ERR_CONNECTION_NOT_PRE_ESTABLISHED = "Connection to splunk server not yet established"
SPLUNK_ERR_INVALID_TIME_RANGE = "Invalid Time range specified, where the end time is less than start time"
SPLUNK_ERR_NEED_PARAM = "One of comment, status, urgency, or owner parameters needs to be supplied to run this action"

# Progress messages
SPLUNK_PROG_GOT_JOB_ID = "Got job id '{job_id}'"
SPLUNK_PROG_TIME_RANGE = "Using range '{range}'"
SPLUNK_PROG_CREATED_QUERY = "Created query '{query}'"
SPLUNK_PROG_CREATING_SEARCH_JOB = "Creating search job"
SPLUNK_PROG_WAITING_ON_JOB_ID = "Waiting for job (id:{job_id}) to finish"
SPLUNK_PROG_CHECKING_STATUS_OF_JOB_ID = "Checking status of job id '{job_id}'"
SPLUNK_PROG_JOB_ID_DONE_RETRIEVING_RESULTS = "Retrieving results for job id '{job_id}'"

# Json keys
SPLUNK_JSON_HOST = "host"
SPLUNK_JSON_DATA = "data"
SPLUNK_JSON_INDEX = "index"
SPLUNK_JSON_QUERY = "query"
SPLUNK_JSON_COUNT = "count"
SPLUNK_JSON_OWNER = "owner"
SPLUNK_JSON_SOURCE = "source"
SPLUNK_JSON_STATUS = "status"
SPLUNK_JSON_EVENTS = "events"
SPLUNK_JSON_URGENCY = "urgency"
SPLUNK_JSON_COMMENT = "comment"
SPLUNK_JSON_ALERT_NAME = "alert"
SPLUNK_JSON_END_TIME = "end_time"
SPLUNK_JSON_TIMEZONE = "timezone"
SPLUNK_JSON_START_TIME = "start_time"
SPLUNK_JSON_SOURCE_TYPE = "sourcetype"
SPLUNK_JSON_LAST_N_DAYS = "last_n_days"
SPLUNK_JSON_TOTAL_EVENTS = "total_events"
SPLUNK_JSON_TOTAL_ALERTS = "total_alerts"
SPLUNK_JSON_HOST_IP_NAME = "host_ip_name"

# Default values
SPLUNK_DEFAULT_EVENT_COUNT = 10
SPLUNK_DEFAULT_ALERT_COUNT = 100
SPLUNK_DEFAULT_SOURCE = "Phantom"
SPLUNK_DEFAULT_SOURCE_TYPE = "Automation/Orchestration Platform"

# HTML search strings:
SPLUNK_POST_DATA_WARN = '<msg type="WARN">'
SPLUNK_SERVER_VERSION = '<s:key name="version">'
SPLUNK_ES_NAME = '<title>SA-EndpointProtection</title>'

# Numeric constants
SPLUNK_MILLISECONDS_IN_A_DAY = 86400000
SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME = 10

# Dictionaries
SPLUNK_STATUS_DICT = {
        "unassigned": 0,
        "new": 1,
        "in progress": 2,
        "pending": 3,
        "resolved": 4,
        "closed": 5
    }
