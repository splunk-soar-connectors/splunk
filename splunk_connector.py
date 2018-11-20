# --
# File: splunk_connector.py
#
# Copyright (c) 2014-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
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
import hashlib
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
        self._state = self.load_state()

        self._container_name_prefix = config.get('container_name_prefix', '')
        container_name_values = config.get('container_name_values')
        if container_name_values:
            self._container_name_values = [x.strip() for x in container_name_values.split(',')]
        else:
            self._container_name_values = []

        return phantom.APP_SUCCESS

    def finalize(self):
        self.save_state(self._state)
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

    def _make_rest_call_retry(self, action_result, endpoint, data, params=None, method=requests.post):
        if params is None:
            params = {}

        RETRY_LIMIT = int(self.get_config().get('retry_count', 3))

        for _ in range(0, RETRY_LIMIT):
            ret_val, resp_data = self._make_rest_call(action_result, endpoint, data, params, method)

            if not phantom.is_fail(ret_val):
                break
        return ret_val, resp_data

    def _make_rest_call(self, action_result, endpoint, data, params=None, method=requests.post):
        if params is None:
            params = {}

        config = self.get_config()
        url = '{0}services/{1}'.format(self._base_url, endpoint)
        self.debug_print('Making REST call to {0}'.format(url))

        try:
            response = method(url, data=data, params=params,
                    auth=(config[phantom.APP_JSON_USERNAME], config[phantom.APP_JSON_PASSWORD]),
                    verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_CONNECTION_FAILED, e), None

        # store the r_text in debug data, it will get dumped in the logs if an error occurs
        if hasattr(action_result, 'add_debug_data'):
            if (response is not None):
                action_result.add_debug_data({'r_status_code': response.status_code})
                action_result.add_debug_data({'r_text': response.text})
                action_result.add_debug_data({'r_headers': response.headers})
            else:
                action_result.add_debug_data({'r_text': 'r is None'})

        if response.status_code != 200:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_200), None

        if endpoint != 'notable_update':
            return phantom.APP_SUCCESS, response.text

        try:
            resp_json = response.json()
        except:
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_JSON), None

        return phantom.APP_SUCCESS, resp_json

    def _get_server_version(self, action_result):

        endpoint = 'server/info'
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, {}, method=requests.get)

        if phantom.is_fail(ret_val):
            return 'FAILURE'

        if consts.SPLUNK_SERVER_VERSION not in resp_data:
            return 'UNKNOWN'

        begin_version = re.search(consts.SPLUNK_SERVER_VERSION, resp_data).end()
        end_version = re.search('</s:key>', resp_data[begin_version:]).start()

        return resp_data[begin_version:begin_version + end_version]

    def _check_for_es(self, action_result):

        endpoint = 'apps/local/SplunkEnterpriseSecuritySuite'
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, {}, method=requests.get)
        if phantom.is_fail(ret_val) or not resp_data:
            return False
        return True

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
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, param[consts.SPLUNK_JSON_DATA], params=get_params)

        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS)

    def _update_event(self, param):

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        if not self._check_for_es(action_result):
            return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_NOT_ES)

        owner = param.get(consts.SPLUNK_JSON_OWNER)
        ids = param.get(consts.SPLUNK_JSON_EVENT_IDS)
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
        ret_val, resp_data = self._make_rest_call_retry(action_result, endpoint, request_body)

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

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]
        last_n_days = param.get(consts.SPLUNK_JSON_LAST_N_DAYS)

        try:
            if last_n_days and int(last_n_days) <= 0:
                return action_result.set_status(phantom.APP_ERROR, "last_n_days parameter must be greater than 0")
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error parsing last_n_days paramter: {0}".format(e))

        search_query = 'search host={0}{1}'.format(ip_hostname, ' earliest=-{0}d'.format(last_n_days) if last_n_days else '')

        return self._run_query(search_query, action_result)

    def _on_poll(self, param):
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        config = self.get_config()
        action_result = self.add_action_result(phantom.ActionResult(dict(param)))
        search_string = config.get('on_poll_query')
        if search_string is None:
            self.save_progress("Need to specify Query String to use polling")
            return self.set_status(phantom.APP_ERROR)

        if (search_string[0] != '|') and (search_string.find('search', 0) != 0):
            search_string = 'search ' + search_string

        search_params = {}
        start_time = self._state.get('start_time')
        if start_time:
            search_params['index_earliest'] = start_time

        if self.is_poll_now():
            search_params['max_count'] = param.get('container_count', 100)
        else:
            search_params['max_count'] = config.get('max_container', 100)

        if search_params['max_count'] <= 0:
            search_params.pop('max_count')

        ret_val = self._run_query(search_string, action_result, search_params)
        if phantom.is_fail(ret_val):
            self.save_progress(action_result.get_message())
            return self.set_status(phantom.APP_ERROR)

        display = config.get('on_poll_display')
        header_set = None
        if display:
            header_set = {x.strip().lower() for x in display.split(',')}

        # Set the most recent event to data[0]
        data = list(reversed(action_result.get_data()))
        self.save_progress("Finished search")

        if data and not self.is_poll_now():
            self._state['start_time'] = data[-1].get('_indextime')

        for item in data:
            container = {}
            cef = {}
            if header_set:
                name_mappings = {}
                for k, v in item.iteritems():
                    if k.lower() in header_set:
                        # Use this to keep the orignal capitalization from splunk
                        name_mappings[k.lower()] = k
                for h in header_set:
                    cef[name_mappings.get(consts.CIM_CEF_MAP.get(h, h), h)] = item.get(name_mappings.get(h, h))
            else:
                for k, v in item.iteritems():
                    cef[consts.CIM_CEF_MAP.get(k, k)] = v
            md5 = hashlib.md5()
            md5.update(item.get('_raw'))
            sdi = md5.hexdigest()
            severity = self._get_splunk_severity(item)
            container['artifacts'] = [
                {
                    'cef': cef,
                    'name': 'Field Values',
                    'source_data_identifier': sdi,
                    'severity': severity
                }
            ]
            container['name'] = self._get_splunk_title(item)
            container['severity'] = severity
            container['source_data_identifier'] = sdi
            ret_val, msg, cid = self.save_container(container)
            if phantom.is_fail(ret_val):
                self.save_progress("Error saving container: {}".format(msg))
                self.debug_print("Error saving container: {} -- CID: {}".format(msg, cid))

        return self.set_status(phantom.APP_SUCCESS)

    def _get_splunk_title(self, item):
        title = self._container_name_prefix
        if not title and not self._container_name_values:
            self._container_name_values.append('source')
        for name in self._container_name_values:
            value = item.get(consts.CIM_CEF_MAP.get(name, name))
            if value:
                title += "{}{} = {}".format(', ' if title else '', name, value)

        if not title:
            time = item.get('_time')
            if time:
                title = "Splunk Log Entry on {}".format(time)
            else:
                title = "Splunk Log Entry"

        return title

    def _get_splunk_severity(self, item):
        severity = item.get('severity')
        severity = consts.SPLUNK_SEVERITY_MAP.get(severity)
        if not severity:
            # Check to see if urgency is set
            urgency = item.get('urgency')
            severity = consts.SPLUNK_SEVERITY_MAP.get(urgency, 'medium')
        return severity

    def _handle_run_query(self, param):

        # Connect
        if (phantom.is_fail(self._connect())):
            return self.get_status()

        search_command = param.get(consts.SPLUNK_JSON_COMMAND)
        search_string = param.get(consts.SPLUNK_JSON_QUERY)
        po = param.get(consts.SPLUNK_JSON_PARSE_ONLY)

        action_result = self.add_action_result(phantom.ActionResult(dict(param)))

        search_query = search_command.strip() + " " + search_string.strip()

        return self._run_query(search_query, action_result, parse_only=po)

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

        version = self._get_server_version(self)
        if version == 'FAILURE':
            return self.append_to_message(consts.SPLUNK_ERR_CONNECTIVITY_TEST)

        is_es = self._check_for_es(self)

        self.save_progress("Detected Splunk {0}server version {1}".format("ES " if is_es else "", version))

        self.debug_print("connect passed")
        return self.set_status_save_progress(phantom.APP_SUCCESS, consts.SPLUNK_SUCC_CONNECTIVITY_TEST)

    def _run_query(self, search_query, action_result, kwargs_create=dict(), parse_only=True):
        """Function that executes the query on splunk"""

        # self.debug_print('Search Query:', search_query)

        RETRY_LIMIT = int(self.get_config().get('retry_count', 3))

        # Validate the search query
        for attempt_count in range(0, RETRY_LIMIT):
            try:
                self._service.parse(search_query, parse_only=parse_only)
                break
            except HTTPError as e:
                return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_INVALID_QUERY, e, query=search_query)
            except Exception as e:
                if attempt_count == RETRY_LIMIT - 1:
                    return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_CONNECTION_FAILED, e)

        self.debug_print(consts.SPLUNK_PROG_CREATED_QUERY.format(query=search_query))

        # Creating search job
        self.save_progress(consts.SPLUNK_PROG_CREATING_SEARCH_JOB)

        # Set any search creation flags here
        kwargs_create.update({'exec_mode': 'normal'})

        self.debug_print("kwargs_create", kwargs_create)

        # Create the job
        for attempt_count in range(0, RETRY_LIMIT):
            try:
                job = self._service.jobs.create(search_query, **kwargs_create)
                break
            except Exception as e:
                if attempt_count == RETRY_LIMIT - 1:
                    return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_UNABLE_TO_CREATE_JOB, e)

        result_count = 0
        while True:
            for attempt_count in range(0, RETRY_LIMIT):
                try:
                    while not job.is_ready():
                        pass
                    job.refresh()
                    break
                except Exception as e:
                    if attempt_count == RETRY_LIMIT - 1:
                        return action_result.set_status(phantom.APP_ERROR, consts.SPLUNK_ERR_CONNECTION_FAILED, e)

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

        try:
            results = splunk_results.ResultsReader(job.results(count=0))
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Error retrieving results", e)

        for result in results:

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
        elif action == "on_poll":
            result = self._on_poll(param)

        return result


if __name__ == '__main__':

    import sys
    import pudb
    import argparse
    import requests

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SplunkConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
