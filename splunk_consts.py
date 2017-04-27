# --
# File: splunk_consts.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2016
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
SPLUNK_SUCC_QUERY_EXECUTED = "Executed splunk query"
SPLUNK_ERR_CONNECTION_FAILED = "Failed to connect to splunk server"
SPLUNK_ERR_UNABLE_TO_CREATE_JOB = "Failed to get a job id from splunk server"
SPLUNK_ERR_CONNECTION_NOT_PRE_ESTABLISHED = "Connection to splunk server not yet established"
SPLUNK_ERR_INVALID_QUERY = "Query invalid '{query}'"
SPLUNK_ERR_INVALID_TIME_RANGE = "Invalid Time range specified, where the end time is less than start time"
SPLUNK_ERR_GET_EVENTS = "Error getting events for alert '{ss_name}' having sid '{sid}'"
SPLUNK_SUCC_CONNECTIVITY_TEST = "Connectivity test passed"
SPLUNK_ERR_CONNECTIVITY_TEST = "Connectivity test failed"

# Progress messages
SPLUNK_PROG_CHECKING_STATUS_OF_JOB_ID = "Checking status of job id '{job_id}'"
SPLUNK_PROG_CREATED_QUERY = "Created query '{query}'"
SPLUNK_PROG_CREATING_SEARCH_JOB = "Creating search job"
SPLUNK_PROG_GOT_JOB_ID = "Got job id '{job_id}'"
SPLUNK_PROG_WAITING_ON_JOB_ID = "Waiting for job (id:{job_id}) to finish"
SPLUNK_PROG_JOB_ID_DONE_RETRIEVING_RESULTS = "Retrieving results for job id '{job_id}'"
SPLUNK_PROG_TIME_RANGE = "Using range '{range}'"

# Json keys
SPLUNK_JSON_HOST_IP_NAME = "host_ip_name"
SPLUNK_JSON_LAST_N_DAYS = "last_n_days"
SPLUNK_JSON_QUERY = "query"
SPLUNK_JSON_TOTAL_EVENTS = "total_events"
SPLUNK_JSON_COUNT = "count"
SPLUNK_JSON_END_TIME = "end_time"
SPLUNK_JSON_START_TIME = "start_time"
SPLUNK_JSON_ALERT_NAME = "alert"
SPLUNK_JSON_TOTAL_ALERTS = "total_alerts"
SPLUNK_JSON_TIMEZONE = "timezone"

SPLUNK_MILLISECONDS_IN_A_DAY = 86400000
SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME = 10
SPLUNK_DEFAULT_ALERT_COUNT = 100
SPLUNK_DEFAULT_EVENT_COUNT = 10
