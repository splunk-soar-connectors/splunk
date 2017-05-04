# --
# File: splunk_connector.py
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

# Phantom imports
import phantom.app as phantom

# THIS Connector imports
import splunk_consts as consts

from splunklib.binding import HTTPError
import splunklib.client as splunk_client
import splunklib.results as splunk_results

import re
import time
import pytz
import requests
import simplejson as json

from pytz import timezone
from datetime import datetime


class SplunkConnector(phantom.BaseConnector):

    ACTION_ID_POST_DATA = "post_data"
    ACTION_ID_RUN_QUERY = "execute_search"
    ACTION_ID_UPDATE_EVENT = "update_event"
    ACTION_ID_GET_HOST_EVENTS = "get_host_events"

    def __init__(self):

        # Call the BaseConnectors init first
        super(SplunkConnector, self).__init__()
        self._service = None
        self._base_url = None

    def initialize(self):

        config = self.get_config()

        self._base_url = 'https://{0}:{1}/'.format(config[phantom.APP_JSON_DEVICE], config[phantom.APP_JSON_PORT])

        return phantom.APP_SUCCESS

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
            return self.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_CONNECTION_FAILED, e)

        # Must return success if we want handle_action to be called
        return phantom.APP_SUCCESS

    def _make_rest_call(self, action_result, endpoint, data, params={}, method=requests.post):

        config = self.get_config()
        url = '{0}services/{1}'.format(self._base_url, endpoint)
        self.debug_print('Making REST call to {0}'.format(url))

        try:
            response = method(url, data=data, params=params,
                    auth=(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD]),
                    verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_CONNECTION_FAILED, e), None

        if endpoint in ['receivers/simple', 'apps/local']:
            if response.status_code == 200:
                return phantom.APP_SUCCESS, response.text
            if consts.SPLUNK_POST_DATA_WARN in response.text:
                return action_result.set_status(phantom.APP_ERROR, response.text[
                    re.search(consts.SPLUNK_POST_DATA_WARN, response.text).end(): re.search('</msg>', response.text).start()]), None
            else:
                return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_200.format(response.status_code, 'Unknown Error')), None

        try:
            resp_json = response.json()
        except:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_JSON), None

        if response.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_200.format(response.status_code, resp_json.get('message', 'Unknown Error'))), None

        return phantom.APP_SUCCESS, resp_json

    def _check_for_es(self, action_result):

        endpoint = 'apps/local'
        ret_val, resp_data = self._make_rest_call(action_result, endpoint, {}, method=requests.get)

        if consts.SPLUNK_ES_NAME in resp_data:
            return True
        return False

    def _post_data(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        host = param.get(consts.SPLUNK_JSON_HOST)
        index = param.get(consts.SPLUNK_JSON_INDEX)
        source = param.get(consts.SPLUNK_JSON_SOURCE, consts.SPLUNK_DEFAULT_SOURCE)
        source_type = param.get(consts.SPLUNK_JSON_SOURCE_TYPE, consts.SPLUNK_DEFAULT_SOURCE_TYPE)

        get_params = {'source': source, 'sourcetype': source_type}

        if host:
            get_params['host'] = host
        if index:
            get_params['index'] = index

        endpoint = 'receivers/simple'
        ret_val, resp_data = self._make_rest_call(action_result, endpoint, param[consts.SPLUNK_JSON_DATA], params=get_params)

        if not ret_val:
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_event(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._check_for_es(action_result):
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_ES)

        ids = param.get(consts.SPLUNK_JSON_EVENTS)
        owner = param.get(consts.SPLUNK_JSON_OWNER)
        status = param.get(consts.SPLUNK_JSON_STATUS)
        comment = param.get(consts.SPLUNK_JSON_COMMENT)
        urgency = param.get(consts.SPLUNK_JSON_URGENCY)

        if not comment and not status and not urgency and not owner:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NEED_PARAM)

        request_body = {"ruleUIDs": ids}

        if owner:
            request_body['newOwner'] = owner
        if status:
            if status not in consts.SPLUNK_STATUS_DICT:
                return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_BAD_STATUS)
            request_body['status'] = consts.SPLUNK_STATUS_DICT[status]
        if urgency:
            request_body['urgency'] = urgency
        if comment:
            request_body['comment'] = comment

        endpoint = 'notable_update'
        ret_val, resp_data = self._make_rest_call(action_result, endpoint, request_body)

        if not ret_val:
            return ret_val

        action_result.add_data(resp_data)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_host_events(self, param):
        """Executes the query to get events pertaining to a host
            Gets the events for a host for the last 'N' number of days
        """

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]
        last_n_days = param[consts.SPLUNK_JSON_LAST_N_DAYS]

        search_query = 'search {} earliest=-{}d'.format(ip_hostname, last_n_days)

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        return self._run_query(search_query, action_result)

    def _handle_run_query(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        search_string = param.get(consts.SPLUNK_JSON_QUERY)

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        # Check if we need to add the search keyword in the start
        if (search_string[0] != '|') and (search_string.find('search', 0) != 0):
            search_string = 'search ' + search_string

        return self._run_query(search_string, action_result)

    def _get_tz_str_from_epoch(self, time_format_str, epoch_milli):

        # Need to convert from UTC to the device's timezone, get the device's tz from config
        config = self.get_config()
        device_tz_sting = config[consts.SPLUNK_JSON_TIMEZONE]

        to_tz = timezone(device_tz_sting)

        utc_dt = datetime.utcfromtimestamp(epoch_milli / 1000).replace(tzinfo=pytz.utc)
        to_dt = to_tz.normalize(utc_dt.astimezone(to_tz))

        # return utc_dt.strftime('%Y-%m-%d %H:%M:%S')
        return to_dt.strftime(time_format_str)

    def _list_alerts(self, param, action_result=None):

        if (not action_result):
            # Create a action result to represent this action
            action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        # If end_time is not given, then end_time is 'now'
        # If start_time is not given, then start_time is SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME
        # days behind end_time
        curr_epoch_msecs = int(time.time()) * 1000
        start_time_msecs = 0
        end_time_msecs = int(phantom.get_value(param, consts.SPLUNK_JSON_END_TIME, curr_epoch_msecs))
        start_time_msecs = int(phantom.get_value(param, consts.SPLUNK_JSON_START_TIME,
                end_time_msecs - (consts.SPLUNK_MILLISECONDS_IN_A_DAY * consts.SPLUNK_NUMBER_OF_DAYS_BEFORE_ENDTIME)))

        if (end_time_msecs < start_time_msecs):
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_TIME_RANGE)

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

        self.save_progress(consts.SPLUNK_PROG_TIME_RANGE, range=json.dumps(kwargs_create))

        count = int(phantom.get_value(param, phantom.APP_JSON_CONTAINER_COUNT, consts.SPLUNK_DEFAULT_ALERT_COUNT))

        # Work of the saved search name, if given
        ss_name = phantom.get_value(self.get_config(), consts.SPLUNK_JSON_ALERT_NAME, None)

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

    def _test_asset_connectivity(self, param):

        if (phantom.is_fail(self._connect())):
            self.debug_print("connect failed")
            self.save_progress(consts.SPLUNK_ERR_CONNECTIVITY_TEST)
            return self.append_to_message(consts.SPLUNK_ERR_CONNECTIVITY_TEST)

        self.save_progress("Splunk server {0} ES".format("has" if self._check_for_es(self) else "does not have"))

        self.debug_print("connect passed")
        return self.set_status_save_progress(phantom.APP_SUCCESS, consts.SPLUNK_SUCC_CONNECTIVITY_TEST)

    def _run_query(self, search_query, action_result, kwargs_create=dict()):
        """Function that executes the query on splunk"""

        # self.debug_print('Search Query:', search_query)

        # Validate the search query
        try:
            self._service.parse(search_query, parse_only=True)
        except HTTPError as e:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_QUERY, e, query=search_query)

        self.debug_print(consts.SPLUNK_PROG_CREATED_QUERY.format(query=search_query))

        # Creating search job
        self.save_progress(consts.SPLUNK_PROG_CREATING_SEARCH_JOB)

        # Set any search creation flags here
        kwargs_create.update({'exec_mode': 'normal'})

        self.debug_print("kwargs_create", kwargs_create)

        # Create the job
        try:
            job = self._service.jobs.create(search_query, **kwargs_create)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_UNABLE_TO_CREATE_JOB, e)

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

        action_result.update_summary({consts.SPLUNK_JSON_TOTAL_EVENTS: result_index})

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

        return result


if __name__ == '__main__':

    import sys
    # import pudb

    # Breakpoint at runtime
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))
        connector = SplunkConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
