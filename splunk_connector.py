# --
# File: splunk_connector.py
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

# Phantom imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# THIS Connector imports
from splunk_consts import *

from splunklib.binding import HTTPError
import splunklib.client as splunk_client
import splunklib.results as splunk_results

import simplejson as json
import time
import re
from datetime import datetime
import calendar
from parse import parse
from pytz import timezone
import pytz


class SplunkConnector(BaseConnector):

    ACTION_ID_RUN_QUERY = "execute_search"
    ACTION_ID_GET_HOST_EVENTS = "get_host_events"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SplunkConnector, self).__init__()
        self._service = None

    def _connect(self):

        if (self._service is not None):
            return phantom.APP_SUCCESS

        config = self.get_config()
        splunk_server = config[phantom.APP_JSON_DEVICE]
        kwargs_config_flags = {
                'host': splunk_server,
                'port': int(phantom.get_value(config, phantom.APP_JSON_PORT, '8089')),
                'username': phantom.get_value(config, phantom.APP_JSON_USERNAME, None),
                'password': phantom.get_value(config, phantom.APP_JSON_PASSWORD, None)}

        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, splunk_server)

        try:
            self._service = splunk_client.connect(**kwargs_config_flags)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, SPLUNK_ERR_CONNECTION_FAILED, e)

        # Must return success if we want handle_action to be called
        return phantom.APP_SUCCESS

    def _get_host_events(self, param):
        """Executes the query to get events pertaining to a host
            Gets the events for a host for the last 'N' number of days
        """

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]
        last_n_days = param[SPLUNK_JSON_LAST_N_DAYS]

        search_query = 'search {} earliest=-{}d'.format(ip_hostname, last_n_days)

        action_result = self.add_action_result(ActionResult(dict(param)))

        return self._run_query(search_query, action_result)

    def _handle_run_query(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        search_string = param.get(SPLUNK_JSON_QUERY)

        action_result = self.add_action_result(ActionResult(dict(param)))

        # Check if we need to add the search keyword in the start
        if (search_string[0] != '|') and (search_string.find('search', 0) != 0):
            search_string = 'search ' + search_string

        return self._run_query(search_string, action_result)

    def _get_tz_str_from_epoch(self, time_format_str, epoch_milli):

        # Need to convert from UTC to the device's timezone, get the device's tz from config
        config = self.get_config()
        device_tz_sting = config[SPLUNK_JSON_TIMEZONE]

        to_tz = timezone(device_tz_sting)

        utc_dt = datetime.utcfromtimestamp(epoch_milli / 1000).replace(tzinfo=pytz.utc)
        to_dt = to_tz.normalize(utc_dt.astimezone(to_tz))

        # return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
        return to_dt.strftime(time_format_str)

    def _list_alerts(self, param, action_result=None):

        if (not action_result):
            # Create a action result to represent this action
            action_result = self.add_action_result(ActionResult(dict(param)))

        # If end_time is not given, then end_time is 'now'
        # If start_time is not given, then start_time is SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME
        # days behind end_time
        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(phantom.get_value(param, SPLUNK_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = int(phantom.get_value(param, SPLUNK_JSON_START_TIME,
                end_time_msecs - (SPLUNK_MILLISECONDS_IN_A_DAY * SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME)))

        if (end_time_msecs < start_time_msecs):
            return action_result.set_status(phantom.APP_ERROR, SPLUNK_ERR_INVALID_TIME_RANGE)

        # From splunk documentation
        # To search with an exact date as boundary, such as from November 5 at 8 PM to November 12 at 8 PM,
        # use the timeformat: %m/%d/%Y:%H:%M:%S
        # TODO, We need not convert the epoch to formatted and then pass the format string also to splunk
        # We should be able to work off of just epoch, however not too sure what the input epoch UTC format
        # is to splunk and the doc is not that clear.
        time_format_str = "%m/%d/%Y:%H:%M:%S"
        earliest_time = '{0}'.format(self._get_tz_str_from_epoch(time_format_str, start_time_msecs))
        latest_time = '{0}'.format(self._get_tz_str_from_epoch(time_format_str, end_time_msecs))

        kwargs_create = {
                'earliest_time': earliest_time,
                'latest_time': latest_time,
                'time_format': time_format_str}
        # kwargs_create = {"time_format": "%m/%d/%Y:%H:%M:%S",
        #         "latest_time": "03/21/2015:14:29:25",
        #         "earliest_time": "03/21/2015:14:24:25"}

        self.save_progress(SPLUNK_PROG_TIME_RANGE, range=json.dumps(kwargs_create))

        count = int(phantom.get_value(param, phantom.APP_JSON_CONTAINER_COUNT, SPLUNK_DEFAULT_ALERT_COUNT))

        # Work of the saved search name, if given
        ss_name = phantom.get_value(self.get_config(), SPLUNK_JSON_ALERT_NAME, None)

        # default to blank
        ss_query = ''

        if (ss_name):
            # create a list of query's is easier then just replacing the ',' with 'OR ss_name=
            #  that way we can work on each one of them seperately, like strip them or add quotes
            #  if not present etc.
            ss_names = ['"{0}"'.format(x.strip(' "')) for x in ss_name.split(',') if len(x.strip()) > 0]
            self.debug_print("ss_names", ss_names)
            ss_query = 'ss_name = ' + ' OR ss_name = '.join(ss_names)

        query = 'search index=_audit action=alert_fired {0} | head {1} | fields ss_name sid trigger_time severity'.format(ss_query, count)

        self.debug_print("query", query)

        self._run_query(query, action_result, kwargs_create)

        return action_result.get_status()

    def _parse_symc_event2(self, raw_event):

        # 01/18/2015 05:04:49 PM
        # LogName=Application
        # SourceName=Symantec AntiVirus
        # EventCode=51
        # EventType=2
        # Type=Error
        # ComputerName=FIREBALL.deshaw.com
        # TaskCategory=None
        # OpCode=None
        # RecordNumber=38315
        # Keywords=Classic
        # Message=
        #
        # Security Risk Found!Trojan.Gen.2 in File: C:\Users\sandhub\AppData\Roaming\WSE_VOSTERAN\UPDATEPROC\UPDATETASK.EXE by: Auto-Protect scan.  Action: Quarantine succeeded : Access denied.  Action Description: The file was quarantined successfully. # noqa
        self.debug_print('splunk_log', raw_event)

        # Add the date
        splunk_log = 'start_time=' + raw_event

        # remove blank lines and merge them with the previous line
        splunk_log = re.sub('\r\n[ ]+\r\n', '', splunk_log)

        self.debug_print('splunk_log', splunk_log)

        # splitlines
        log_lines = splunk_log.splitlines()

        self.debug_print('log_lines', log_lines)

        event = dict([(y[0], y[1]) for y in [x.split('=') for x in log_lines if (x.find('=') != -1)]])

        # Parse the message
        if ('Message' in event):
            message = event['Message']
            message_parsed = parse("Security Risk Found!{virus_name} in File: {file_path} by: {scan_name} Action: {action_taken} Action Description:{action_description}", message)
            # print message_parsed.named
            event.update(message_parsed.named)

        event = dict([(k.strip(), v.strip()) for k, v in event.iteritems()])

        self.debug_print('event', event)

        # The output looks like the following
        # {
        #     "start_time": "01/18/2015 05:04:49 PM",
        #     "LogName": "Application",
        #     "SourceName": "Symantec AntiVirus",
        #     "EventCode": "51",
        #     "EventType": "2",
        #     "Type": "Error",
        #     "ComputerName": "FIREBALL.deshaw.com",
        #     "TaskCategory": "None",
        #     "OpCode": "None",
        #     "RecordNumber": "38315",
        #     "Keywords": "Classic",
        #     "Message": "Security Risk Found!Trojan.Gen.2 in File: C:\\Users\\sandhub\\AppData\\Roaming\\WSE_VOSTERAN\\UPDATEPROC\\UPDATETASK.EXE by: Auto-Protect scan.  Action: Quarantine succeeded : Access denied.  Action Description: The file was quarantined successfully.", # noqa
        #     "virus_name": "Trojan.Gen.2",
        #     "file_path": "C:\\Users\\sandhub\\AppData\\Roaming\\WSE_VOSTERAN\\UPDATEPROC\\UPDATETASK.EXE",
        #     "scan_name": "Auto-Protect scan.",
        #     "action_taken": "Quarantine succeeded : Access denied.",
        #     "action_description": "The file was quarantined successfully."
        # }

        # map['cef_key'] = ['event_key']
        symc_virus_detected_cef_map = {
                "startTime": "start_time",
                "sourceHostName": "Computername",
                "deviceAction": "action_taken",
                "filePath": "file_path",
                "deviceEventCategory": "TaskCategory",
                "deviceCustomString1": "virus_name",
                "message": "Message"}

        cef = phantom.get_cef_data(event, symc_virus_detected_cef_map)

        cef['deviceCustomString1Label'] = 'Virus name'
        cef['startTime'] = calendar.timegm(datetime.strptime(cef['startTime'], '%m/%d/%Y %I:%M:%S %p').utctimetuple()) * 1000
        cef['endTime'] = cef['startTime'] + 1

        # self.debug_print('cef', cef)

        return {'raw': event, 'cef': cef}

    def _parse_symc_event(self, raw_event):
        # For sepm virus detection trigger this is one of the events, all in a single line
        #
        # <54>Jan 12 19:08:22 SymantecServer sepm.phantom.us: Virus found,
        # IP Address: 10.17.2.200,
        # Computer name: victim,
        # Source: Real Time Scan,
        # Risk name: Infostealer,
        # Occurrences: 1,
        # C:\infectme\zeus\5f9bbeb166f3ca9f6ad27b6475615d0d.exe,
        # '',
        # Actual action: Cleaned by deletion,
        # Requested action: Cleaned,
        # Secondary action: Quarantined,
        # Event time: 2015-01-13 03:06:39,
        # Inserted: 2015-01-13 03:08:22,
        # End: 2015-01-13 03:06:39,
        # Last update time: 2015-01-13 03:08:22,
        # Domain: Default,
        # Group: My Company\Default Group,
        # Server: sepm.phantom.us,
        # User: phantom,
        # Source computer: ,
        # Source IP: ,
        # Disposition: Good,
        # Download site: null,
        # Web domain: null,
        # Downloaded by: null,
        # Prevalence: Reputation was not used in this detection.,
        # Confidence: Reputation was not used in this detection.,
        # URL Tracking Status: Off,
        # ,
        # First Seen: Reputation was not used in this detection.,
        # Sensitivity: Low,
        # MDS,
        # Application hash: ,
        # Hash type: SHA1,
        # Company name: ,
        # Application name: ,
        # Application version: ,
        # Application type: -1,
        # File size (bytes): 0,
        # Category set: Malware,
        # Category type: Virus

        # If the event was guaranteed to be well formed, creating a json of the same would be a
        # one line python comprehension with two splits, We can still take care of that scenario,
        # but might make the code very ugly. For now, go the manual split way.

        self.debug_print(raw_event)
        # Take the the raw event and split it
        event_split = phantom.get_list_from_string(raw_event, remove_duplicates=False)

        event = dict()
        # ignore the first element, that's the header
        event_split.pop(0)

        for curr_entry in event_split:

            # self.debug_print ('Curr val: {0}'.format(curr_entry))

            # One has to do multiple such checks because the format that we encounter is not well formed

            # if it's a windows path, we've noticed this one comes without a key, but since it will contain a ':'
            # after the drive letter one cannot split on it
            if (phantom.is_windows_path(curr_entry)):
                k = 'File Path'
                v = curr_entry
            elif (curr_entry.find(':') == -1):  # handle the case if the ':' is not present.
                k = curr_entry
                v = None
            else:
                k, v = curr_entry.split(':', 1)

            k = k.strip() if k else k
            v = v.strip() if v else v

            # self.debug_print ("k: '{0}' v: '{1}'".format(k, v))

            if (k) and (len(k) > 0):
                event.update({k: v})

        self.debug_print('event', event)

        self.debug_print('File Path', event['File Path'])

        # map['cef_key'] = ['event_key']
        symc_virus_detected_cef_map = {
                "fileSize": "File size (bytes)",
                "requestClientApplication": "Application name",
                "sourceHostName": "Computer name",
                "endTime": "End",
                "fileHash": "Application hash",
                "deviceAction": "Actual action",
                "deviceHostname": "Server",
                "filePath": "File Path",
                "destinationNtDomain": "Domain",
                "deviceEventCategory": "Category type",
                "startTime": "Event time",
                "sourceAddress": "IP Address",
                "destinationUserName": "User",
                "deviceCustomString1": "Risk name"}

        cef = phantom.get_cef_data(event, symc_virus_detected_cef_map)

        cef['deviceCustomString1Label'] = 'Virus name'
        cef['startTime'] = calendar.timegm(datetime.strptime(cef['startTime'], '%Y-%m-%d %H:%M:%S').utctimetuple()) * 1000
        cef['endTime'] = calendar.timegm(datetime.strptime(cef['endTime'], '%Y-%m-%d %H:%M:%S').utctimetuple()) * 1000

        # self.debug_print('cef', cef)

        return {'raw': event, 'cef': cef}

    def _parse_event(self, event):
        """Converts splunk events to json, containing raw and cef jsons"""

        a_raw = event['_raw']

        # splunk manages multiple types of events, each one needs to be parsed
        # differently, so first figure out if we understand this event
        if (a_raw.find('SymantecServer') != -1):
            return self._parse_symc_event(a_raw)
        elif (a_raw.find('Symantec AntiVirus') != -1):
            return self._parse_symc_event2(a_raw)

        return {'raw': event, 'cef': None}

    def _test_asset_connectivity(self, param):

        if (phantom.is_fail(self._connect())):
            self.debug_print("connect failed")
            self.save_progress(SPLUNK_ERR_CONNECTIVITY_TEST)
            return self.append_to_message(SPLUNK_ERR_CONNECTIVITY_TEST)

        self.debug_print("connect passed")
        return self.set_status_save_progress(phantom.APP_SUCCESS, SPLUNK_SUCC_CONNECTIVITY_TEST)

    def _run_query(self, search_query, action_result, kwargs_create=dict()):
        """Function that executes the query on splunk"""

        # self.debug_print('Search Query:', search_query)

        # Validate the search query
        try:
            self._service.parse(search_query, parse_only=True)
        except HTTPError as e:
            return action_result.set_status(phantom.APP_ERROR, SPLUNK_ERR_INVALID_QUERY, e, query=search_query)

        self.debug_print(SPLUNK_PROG_CREATED_QUERY.format(query=search_query))

        # Creating search job
        self.save_progress(SPLUNK_PROG_CREATING_SEARCH_JOB)

        # Set any search creation flags here
        kwargs_create.update({'exec_mode': 'normal'})

        self.debug_print("kwargs_create", kwargs_create)

        # Create the job
        try:
            job = self._service.jobs.create(search_query, **kwargs_create)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, SPLUNK_ERR_UNABLE_TO_CREATE_JOB, e)

        result_count = 0
        while True:
            while not job.is_ready():
                pass
            job.refresh()
            stats = {'is_done': job['isDone'],
                     'progress': float(job['doneProgress']) * 100,
                      'scan_count': int(job['scanCount']),
                      'event_count': int(job['eventCount']),
                      'result_count': int(job['resultCount'])}
            status = ("Progress: %(progress)03.1f%%   %(scan_count)d scanned   "
                      "%(event_count)d matched   %(result_count)d results") % stats
            self.send_progress(status)
            if stats['is_done'] == '1':
                result_count = stats['result_count']
                break
            time.sleep(2)

        self.send_progress("Parsing results...")
        result_index = 0
        ten_percent = float(result_count) * 0.10
        for result in splunk_results.ResultsReader(job.results(count=0)):

            if isinstance(result, dict):

                action_result.add_data(result)

            result_index += 1

            if (result_index % ten_percent) == 0:
                status = "Finished parsing {0:.1%} of results".format((float(result_index) / float(result_count)))
                self.send_progress(status)

        action_result.update_summary({SPLUNK_JSON_TOTAL_EVENTS: result_index})

        return action_result.set_status(phantom.APP_SUCCESS)

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

        if (action == self.ACTION_ID_GET_HOST_EVENTS):
            result = self._get_host_events(param)
        elif (action == self.ACTION_ID_RUN_QUERY):
            result = self._handle_run_query(param)
        elif (action == phantom.ACTION_ID_TEST_ASSET_CONNECTIVITY):
            result = self._test_asset_connectivity(param)

        return result
