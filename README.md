[comment]: # "Auto-generated SOAR connector documentation"
# Splunk

Publisher: Splunk  
Connector Version: 2.16.0  
Product Vendor: Splunk Inc.  
Product Name: Splunk Enterprise  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 6.1.0  

This app integrates with Splunk to update data on the device, in addition to investigate and ingestion actions

[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2023 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## App's Token-Based Authentication Workflow

-   This app also supports API token based authentication.

-   Please follow the steps mentioned in this
    [documentation](https://docs.splunk.com/Documentation/Splunk/9.0.0/Security/CreateAuthTokens) to
    generate an API token.

      
    **NOTE -** If the username/password and API token are both provided then the API token will be
    given preference and a token-based authentication workflow will be used.

## Splunk-SDK

This app uses the Splunk-SDK module, which is licensed under the Apache Software License, Copyright
(c) 2011-2023 Splunk, Inc.

## State File Permissions

Please check the permissions for the state file as mentioned below.

#### State Filepath

-   For Non-NRI Instance:
    /opt/phantom/local_data/app_states/91883aa8-9c81-470b-97a1-5d8f7995f560/{asset_id}\_state.json
-   For NRI Instance:
    /phantomcyber/local_data/app_states/91883aa8-9c81-470b-97a1-5d8f7995f560/{asset_id}\_state.json

#### State File Permissions

-   File Rights: rw-rw-r-- (664) (The splunk phantom user should have read and write access for the state
    file)
-   File Owner: appropriate splunk phantom user

## Required Permissions for Post Data Action

For sending events to Splunk Platform, the User configured in the asset would require **edit_tcp** capability. Follow the below steps to configure:
- Login to the Splunk Platform
- Go to **Setting > Roles**
- Click on role of the user configured in the asset(example: user) and go to **Capabilities**.
- Search for '**edit_tcp**' in the capabilities enable it for the particular role.
- To check if the capability is given to your user, go to **Settings > Users** and in the **Edit dropdown** and select **View Capabilities**.
- Search for '**edit_tcp**' and if a tick besides it appears then the permission has been enabled for the user.

## Asset Configuration Parameters

-   container_name_prefix:
    -   Name to give containers created via ingestion

    -   User can select a field name from the events data

          

        -   If the provided field exists, then container_name_prefix will be the value against the
            provided field from the events data
        -   If the provided field does not exist, then container_name_prefix will be the provided
            field name itself

    -   If the container_name_prefix parameter is not provided:

          

        -   If the event data contains '\_time' field, then container_name_prefix will be 'Splunk
            Log Entry on \<value of the \_time field>'
        -   If the event data does not contain '\_time' field, then container_name_prefix will be
            'Splunk Log Entry'

    -   Users can provide a string. Example: Test title
-   container_name_values:
    -   Values to append to the container name created via ingestion

    -   User can provide CIM fields

    -   If the container_name_values parameter is provided:

          

        -   If the provided field exists, then container_name_values will be the value against the
            provided CIM field or its CIM field mapping from the events data
        -   If neither a CIM field mapping nor CIM field itself is present in the event data, then
            container_name_values will be the CIM field mapping or CIM field

    -   If the container_name_values parameter is not provided:

          

        -   If 'container_name_prefix' parameter is not provided, then container_name_values will be
            'source'
        -   If 'container_name_prefix' parameter is provided, then container_name_values will be
            empty

    -   Users can provide a comma-separated string. Example: test1, test2
-   Container count to update the state file:
    -   This parameter will allow the user to specify the number of containers and will only be used
        in scheduled or interval polling
    -   Everytime the count of the containers reaches the count provided by the user, the
        "start_time" stored in the state file will be updated by the index time of that event
    -   The default value is 100
-   splunk_app:
    -   The app context of the namespace
    -   As per Splunk SDK's documentation, if the splunk_app parameter is not provided, then
        "system" will be considered as splunk_app
-   splunk_owner:
    -   The owner context of the namespace
    -   As per Splunk SDK's documentation, if the splunk_owner parameter is not provided, then
        "nobody" will be considered as splunk_owner
-   retry_count:
    -   Number of retries
    -   To ask a query to the Splunk server using the splunklib library, first, the query asked by
        the user is to be parsed. Then, this parsed query is used to create a job and once this job
        is ready the results are ready to be fetched. So while performing any of the above steps, if
        any exception occurs then, the code will retry that step for the number of retries provided
        in the "retry count" configuration parameter.
    -   It will also be used if an error or an exception occurs while posting the data in the "post
        data" action or modifying the event in the "update event" action.
-   remove_empty_cef:
    -   Remove CEF fields having empty values from the artifact
    -   It allows the user to remove CEF fields having empty values from the artifact during
        ingestion. If the value of the parameter is 'true', CEF fields having empty values will be
        removed.
-   sleeptime_in_requests:
    -   The time to wait for next REST call(max 120 seconds)
    -   It allows the user to add sleep time between the REST calls while performing the
        "run_query", "update_event", "get host events" and "on poll" action.
-   on_poll_display:
    -   Fields to save with On Poll
    -   Users can select the fields from the events which the user wants to ingest in the artifact
    -   If the on_poll_display parameter is not provided, then all the fields that are extracted
        from the events will be ingested in the respective artifacts
    -   Users can provide comma-separated field names. Example: field1, field2, field3
-   If the on_poll_query(query to use with On Poll) parameter is not provided, then an error message
    will be returned  
-   If the on_poll_command(command for the query to use with On Poll) parameter is not provided and
    the on_poll_query does not start with "|" or "search", then the "search" keyword is added at
    the beginning of the on_poll_query  
    Example:
    -   on_poll_command: None  
        on_poll_query: index = "main"  
        Final query generated internally: search index = "main"
-   If the on_poll_command parameter is not provided and the on_poll_query starts with "|" or
    "search", then the final query would be the same as the query provided in the on_poll_query
    parameter  
    Example:
    -   on_poll_command: None  
        on_poll_query: search index = "main"  
        Final query generated internally: search index = "main"
-   If on_poll_command parameter is provided, then query is formed as: {on_poll_command}
    {on_poll_query}  
    Example:
    -   on_poll_command: search  
        on_poll_query: index = "main"  
        Final query generated internally: search index = "main"

## Update Event

-   To execute this action successfully, the minimum role required is "ess_analyst", but the user
    can have other roles too.

-   If the **wait_for_confirmation** parameter is False (which is the default), it will be faster
    but there will be no confirmation that the notable ID corresponded with an actual notable event.
    Setting it to True will cause the action to take longer because it will require an SPL search,
    but it will provide more assurance that the update took place.

-   The action updates the event for the provided "event_id". If the **wait_for_confirmation**
    parameter is True, the action validates the "event_id" provided by the user using the search
    command: 'search \`notable\` | search event_id="\<event_id>"'.

      

    -   If this search command returns more than 0 results, the action updates the event.
    -   If this search command does not return any results then, the action fails with the message
        "Please provide a valid event ID".

-   Use integer status field for custom status. Example: 1 For New, 2 for In progress, etc.

## On Poll

-   There are two approaches to polling as mentioned below.

      

    -   POLL NOW (Manual polling)

          

        -   It will fetch the data every time as per the corresponding asset configuration
            parameters. It doesn’t store the last run context of the fetched data.

    -   Scheduled/Interval Polling

          

        -   The ingestion action will be triggered after each specified time interval. It stores the
            last run context of the fetched data and starts fetching new data based on the
            combination of the values of stored context for the previous ingestion run and the
            corresponding asset configuration parameters.

-   Notes

      

    -   In case "on poll" returns any 4XX except 403, validate your search Query on Splunk
    -   Sample "Query" to use with On Poll: index="\_internal" | stats count by host, source,
        sourcetype | head 5 | rename host as h0st | rename source as devicehostname
    -   Sample "Fields to save with On Poll" (if not provided, "on poll" will store all the fields):
        source,sourcetype,hostname
    -   For the **on_poll_parse_only** parameter, if **True** , disables the expansion of search due
        to evaluation of sub-searches, time term expansion, lookups, tags, eventtypes, and
        sourcetype aliases. This parameter is used for the validation of the Splunk query before
        fetching the results
    -   If multiple severities are returned for the incident in the "on poll" action, then the
        highest "severity" will be given priority. If the "severity" is not present in the incident,
        then the "urgency" of the incident will be considered. If the "urgency" is also not present,
        then the ingested container "severity" will be taken as "medium" by default.

      

-   Helpful examples to run on poll

      

    1.  The query will fetch top 10 events from the result of index = "main" search.
        -   on_poll_command: "search"  
        -   on_poll_query: index = "main" | head 10  
        -   Final query generated internally: search index = "main" | head 10  
    2.  The query will execute the query saved in the savedsearch named "Dashboard Views - Action
        History".
        -   on_poll_command: "savedsearch"  
        -   on_poll_query: "Dashboard Views - Action History"  
        -   Final query generated internally: savedsearch "Dashboard Views - Action History"  
    3.  The query will perform statistics for datamodel and will give total count of events fetched
        for datamodel = authentication.
        -   on_poll_command: "tstats"  
        -   on_poll_query: "count from datamodel=Authentication"  
        -   Final query generated internally: "tstats count from datamodel=Authentication"  
    4.  The query will display field "a" in table format for the results fetched from 'search index
        = "\_internal"' search.
        -   on_poll_command: None  
        -   on_poll_query: index = "\_internal" | table a  
        -   Final query generated internally: search index = "\_internal" | table a  
    5.  This query will fetch all the events with sourcetype = "modular_alerts:notable",
        app="phantom", and user="admin".
        -   on_poll_command: None  
        -   on_poll_query: index=\* sourcetype="modular_alerts:notable" app="phantom" user="admin"  
        -   Final query generated internally: search index=\* sourcetype="modular_alerts:notable"
            app="phantom" user="admin"  
    6.  This query will get the count of the events that are indexed in index named "main".
        -   on_poll_command: None  
        -   on_poll_query: index="main" | stats count  
        -   Final query generated internally: search index="main" | stats count  
    7.  This query will add a field with name = "a" and value = "abc" in all the events that are
        indexed in index named "main".
        -   on_poll_command: None  
        -   on_poll_query: index="main" | eval a = "abc"  
        -   Final query generated internally: search index="main" | eval a = "abc"  
    8.  This query will fetch only the sourcetype of all the events that are indexed in index named
        "main".
        -   on_poll_command: None  
        -   on_poll_query: index="main" | fields sourcetype  
        -   Final query generated internally: search index="main" | fields sourcetype  
    9.  This query will fetch all the events having tag = error and index = main.
        -   on_poll_command: None  
        -   on_poll_query: index="\_internal" tag=error  
        -   Final query generated internally: search index="\_internal" tag="error"  
    10. This query will show the data of "ppf_action_history_searches" lookup.
        -   on_poll_command: None  
        -   on_poll_query: |inputlookup ppf_action_history_searches  
        -   Final query generated internally: |inputlookup ppf_action_history_searches  

## Naming Ingested Containers

By default, the "source" field is used to name the ingested containers. To customize the container
names, use the two settings in the asset configuration. For example, if a hostname is expected in
the container name, the "Name to give containers created via ingestion" parameter can be set to
"Notable Splunk Event" and "Values to append to container name" parameter can be set to "host". This
will set the container name to "Notable Splunk Event, host=my.sample.host". The appended values can
be a comma-separated list.

## Special characters present in the Splunk query can affect the output

The user must use appropriate special characters in the query according to individual use-case
otherwise the query will end up providing unexpected results. Following is a list of several such
special characters:

-   Non-breaking space
-   Soft hyphen
-   Micro symbol
-   Division symbol
-   Non-breaking hyphen
-   En dash
-   Em dash
-   Ellipsis

There can exist more such characters apart from the ones listed above.

## Port Information

The app uses HTTP/ HTTPS protocol for communicating with the Splunk server. Below are the default
ports used by Splunk SOAR.

|         SERVICE NAME | TRANSPORT PROTOCOL | PORT |
|----------------------|--------------------|------|
|         http         | tcp                | 80   |
|         https        | tcp                | 443  |

8089 is the default port used by Splunk Server.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Splunk Enterprise asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device** |  required  | string | Device IP/Hostname
**port** |  optional  | numeric | Port
**username** |  optional  | string | Username
**password** |  optional  | password | Password
**api_token** |  optional  | password | API token
**splunk_owner** |  optional  | string | The owner context of the namespace
**splunk_app** |  optional  | string | The app context of the namespace
**timezone** |  required  | timezone | Splunk Server Timezone
**verify_server_cert** |  optional  | boolean | Verify Server Certificate
**on_poll_command** |  optional  | string | Command for query to use with On Poll
**on_poll_query** |  optional  | string | Query to use with On Poll
**on_poll_display** |  optional  | string | Fields to save with On Poll
**on_poll_parse_only** |  optional  | boolean | Parse Only
**max_container** |  optional  | numeric | Max events to ingest for Scheduled Polling (Default: 100)
**container_update_state** |  optional  | numeric | Container count to update the state file
**container_name_prefix** |  optional  | string | Name to give containers created via ingestion
**container_name_values** |  optional  | string | Values to append to container name
**retry_count** |  optional  | numeric | Number of retries
**remove_empty_cef** |  optional  | boolean | Remove CEF fields having empty values from the artifact
**sleeptime_in_requests** |  optional  | numeric | The time to wait for next REST call (max 120 seconds)
**include_cim_fields** |  optional  | boolean | Option to keep original Splunk CIM together with SOAR CEF fields

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity. This action logs into the device to check the connection and credentials  
[get host events](#action-get-host-events) - Get events pertaining to a host that have occurred in the last 'N' days  
[on poll](#action-on-poll) - Ingest logs from the Splunk instance  
[run query](#action-run-query) - Run a search query on the Splunk device. Please escape any quotes that are part of the query string  
[update event](#action-update-event) - Update a notable event  
[post data](#action-post-data) - Post data to Splunk  

## action: 'test connectivity'
Validate the asset configuration for connectivity. This action logs into the device to check the connection and credentials

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get host events'
Get events pertaining to a host that have occurred in the last 'N' days

Type: **investigate**  
Read only: **True**

<ul><li>The <b>last_n_days</b> parameter must be greater than 0.</li><li>The action will search for the events of the hostname (provided in the 'ip_hostname' parameter) in the default index configured on the Splunk instance.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** |  required  | Hostname/IP to search the events of | string |  `ip`  `host name` 
**last_n_days** |  optional  | Number of days ago | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip_hostname | string |  `ip`  `host name`  |   test_host 
action_result.parameter.last_n_days | numeric |  |   2 
action_result.data.\*._bkt | string |  |  
action_result.data.\*._cd | string |  |  
action_result.data.\*._indextime | string |  |  
action_result.data.\*._raw | string |  |  
action_result.data.\*._serial | string |  |  
action_result.data.\*._si | string |  |  
action_result.data.\*._sourcetype | string |  |  
action_result.data.\*._time | string |  |  
action_result.data.\*.host | string |  `host name`  |  
action_result.data.\*.index | string |  |  
action_result.data.\*.linecount | string |  |  
action_result.data.\*.source | string |  |  
action_result.data.\*.sourcetype | string |  |  
action_result.data.\*.splunk_server | string |  `host name`  |  
action_result.summary.sid | string |  |   1612177958.977510 
action_result.summary.total_events | numeric |  |  
action_result.message | string |  |   Sid: 1621953772.25264, Total events: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'on poll'
Ingest logs from the Splunk instance

Type: **ingest**  
Read only: **True**

The configured query is what will be used during ingestion. If you only wish to show certain fields, then you can specify these as a comma-separated list in the configuration. If left unspecified, all available fields will be added to each artifact. When limiting the number of events to ingest, it will ingest the most recent events.<br><br>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** |  optional  | Parameter ignored in this app | numeric | 
**start_time** |  optional  | Parameter ignored in this app | numeric | 
**end_time** |  optional  | Parameter ignored in this app | numeric | 
**container_count** |  optional  | Maximum number of events to query for | numeric | 
**artifact_count** |  optional  | Parameter ignored in this app | numeric | 

#### Action Output
No Output  

## action: 'run query'
Run a search query on the Splunk device. Please escape any quotes that are part of the query string

Type: **investigate**  
Read only: **True**

By default, the widget for the &quot;run query&quot; action will show the host, time, and raw fields. If you would like to see specific fields parsed out, they can be listed in a comma-separated format in the &quot;display&quot; parameter.<br><br>Please keep in mind that Splunk does not always return all possible fields. Splunk may not return fields that are calculated or not present in the event.<br><br>To work around this you can force Splunk to return specific fields by using the &quot;fields&quot;. By appending &quot;| fields + \*&quot; to your query, Splunk will return every field. You can replace the asterisk with a comma-separated list of fields to only return specific fields.<br><br>Finally, some searches (such as those based on data models) can contain name-spaced fields. If a data model called &quot;my_model&quot; with a search &quot;my_search&quot; has a field &quot;hash&quot; then the field will be named &quot;my_search.hash&quot; and that is what must be used in the Splunk fields command and the display parameter. If using a non-global lookup file that is only accessible by a specific Splunk App, make sure to note the specific Splunk App in your asset configuration. The <b>parse_only</b> parameter, if <b>True</b>, it disables the expansion of search due to evaluation of sub-searches, time term expansion, lookups, tags, eventtypes, and sourcetype alias. This parameter is used for the validation of the Splunk query before fetching the results.<br><br>Learn more below:<ul><li><a href='https://docs.splunk.com/Documentation/Splunk/8.2.5/SearchReference/SearchTimeModifiers' target='_blank'>Time modifiers</a></li><li><a href='https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch#search.2Fjobs' target='_blank'>Splunk REST APIs</a></li><li><a href='https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/howtousesplunkpython/howtorunsearchespython/' target='_blank'>Splunk SDK</a></li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**command** |  optional  | Beginning command (in Splunk Processing Language) | string | 
**query** |  required  | Query to run (in Splunk Processing Language) | string |  `splunk query` 
**display** |  optional  | Display fields (comma-separated) | string | 
**parse_only** |  optional  | Parse only | boolean | 
**attach_result** |  optional  | Attach result to the vault | boolean | 
**start_time** |  optional  | Earliest time modifier | string | 
**end_time** |  optional  | Latest time modifier | string | 
**search_mode** |  optional  | Search mode | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.attach_result | boolean |  |   True  False 
action_result.parameter.command | string |  |   savedsearch 
action_result.parameter.display | string |  |   _time  index 
action_result.parameter.end_time | string |  |   -2d  2022-03-18T16:12:09.130+00:00 
action_result.parameter.parse_only | boolean |  |   True  False 
action_result.parameter.query | string |  `splunk query`  |   "Send to test" 
action_result.parameter.search_mode | string |  |   smart 
action_result.parameter.start_time | string |  |   -2d  2022-03-18T16:12:07.130+00:00 
action_result.data.\*._bkt | string |  |  
action_result.data.\*._cd | string |  |  
action_result.data.\*._indextime | string |  |  
action_result.data.\*._key | string |  |   1659398400|_audit 
action_result.data.\*._kv | string |  |  
action_result.data.\*._origtime | string |  |   1659398400 
action_result.data.\*._raw | string |  |  
action_result.data.\*._serial | string |  |  
action_result.data.\*._si | string |  |  
action_result.data.\*._sourcetype | string |  |  
action_result.data.\*._subsecond | string |  |  
action_result.data.\*._time | string |  |  
action_result.data.\*._value | string |  |   184 
action_result.data.\*.a | string |  |  
action_result.data.\*.content.app | string |  |   search 
action_result.data.\*.content.host | string |  |  
action_result.data.\*.content.info | string |  |  
action_result.data.\*.content.search | string |  |  
action_result.data.\*.content.search_type | string |  |  
action_result.data.\*.content.sid | string |  |  
action_result.data.\*.content.source | string |  |  
action_result.data.\*.content.sourcetype | string |  |  
action_result.data.\*.content.uri | string |  |   /en-US/app/search/search?q=search%20index%3Dmain%20%7C%20head%2010&sid=1651356328.532450&display.page.search.mode=smart&dispatch.sample_ratio=1&workload_pool=&earliest=-24h%40h&latest=now 
action_result.data.\*.content.view | string |  |   search 
action_result.data.\*.count | string |  |  
action_result.data.\*.count(host) | string |  |  
action_result.data.\*.event | string |  |   {"data": {"count": 3, "size": 112, "transform": "access_app_tracker"}, "version": "1.0"} 
action_result.data.\*.host | string |  `host name`  |   10.1.67.187:8088 
action_result.data.\*.index | string |  |  
action_result.data.\*.is_Acceleration_Jobs | string |  |  
action_result.data.\*.is_Adhoc_Jobs | string |  |  
action_result.data.\*.is_Failed_Jobs | string |  |  
action_result.data.\*.is_Realtime_Jobs | string |  |  
action_result.data.\*.is_Scheduled_Jobs | string |  |  
action_result.data.\*.is_Subsearch_Jobs | string |  |  
action_result.data.\*.is_not_Acceleration_Jobs | string |  |  
action_result.data.\*.is_not_Adhoc_Jobs | string |  |  
action_result.data.\*.is_not_Failed_Jobs | string |  |  
action_result.data.\*.is_not_Realtime_Jobs | string |  |  
action_result.data.\*.is_not_Scheduled_Jobs | string |  |  
action_result.data.\*.is_not_Subsearch_Jobs | string |  |  
action_result.data.\*.linecount | string |  |  
action_result.data.\*.source | string |  |  
action_result.data.\*.sourcetype | string |  |  
action_result.data.\*.spent | string |  |   223 
action_result.data.\*.splunk_server | string |  `host name`  |  
action_result.data.\*.user | string |  |  
action_result.data.\*.values(source) | string |  |  
action_result.summary.sid | string |  |   1612177958.977510 
action_result.summary.total_events | numeric |  |   2 
action_result.message | string |  |   Sid: 1612177958.977510, Total events: 2 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'update event'
Update a notable event

Type: **generic**  
Read only: **False**

The <b>event_ids</b> parameter takes a single event_id (which has the format: 68E08B8B-A853-3A20-9768-231C97B7EE76@@notable@@a4bd78810ae8e03e285e552fac0ddb23) or an adaptive response SID + RID combo (which has the format: scheduler__admin__SplunkEnterpriseSecuritySuite__RMD515d4671130158e57_at_1532441220_4982+0).<br><br>NOTE: This action only works with a notable event from Splunk ES.<br><br>Second Note: The <b>status</b> parameter takes a string value, but custom status values are unique to installation and not available at app creation. The <b>integer_status</b> parameter takes a positive integer denoting the custom value desired. This integer must be determined by the customer on-site. If set it will override <b>status</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_ids** |  required  | Event ID to update | string |  `splunk notable event id` 
**comment** |  optional  | New comment for the event | string | 
**status** |  optional  | New status for the event | string | 
**integer_status** |  optional  | Integer representing custom status value | numeric | 
**urgency** |  optional  | New urgency for the event | string | 
**owner** |  optional  | New owner for the event | string | 
**wait_for_confirmation** |  optional  | Validate event_ids | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.comment | string |  |   test comment 
action_result.parameter.event_ids | string |  `splunk notable event id`  |   1542751027.136723+0 
action_result.parameter.integer_status | numeric |  |   1 
action_result.parameter.owner | string |  |   test 
action_result.parameter.status | string |  |   new 
action_result.parameter.urgency | string |  |   low 
action_result.parameter.wait_for_confirmation | boolean |  |   False  True 
action_result.data.\*.failure_count | numeric |  |   0 
action_result.data.\*.message | string |  |   1 event updated successfully 
action_result.data.\*.success | boolean |  |   False  True 
action_result.data.\*.success_count | numeric |  |   1 
action_result.summary.sid | string |  |   1612177958.977510 
action_result.summary.updated_event_id | string |  |   2CF264EE-6016-4F6A-BCC3-4B7251E113F7@@notable@@035142b19c09ab645c6bbfb847e866f4 
action_result.message | string |  |   Updated event id: 2CF264EE-6016-4F6A-BCC3-4B7251E113F7@@notable@@035142b19c09ab645c6bbfb847e866f4 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'post data'
Post data to Splunk

Type: **generic**  
Read only: **False**

This action creates an event on Splunk with the data included in the <b>data</b> parameter. If not specified the parameters will default to the following:<ul><li><b>host</b> - The IP of the Splunk Phantom instance running the action.</li><li><b>index</b> - The default index configured on the Splunk instance.</li><li><b>source</b> - &quot;Phantom&quot;.</li><li><b>source_type</b> - &quot;Automation/Orchestration Platform&quot;.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**data** |  required  | Data to post | string | 
**host** |  optional  | Host for event | string |  `ip`  `host name` 
**index** |  optional  | Index to send event to | string | 
**source** |  optional  | Source for event | string | 
**source_type** |  optional  | Type of source for event | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.data | string |  |   test_data 
action_result.parameter.host | string |  `ip`  `host name`  |   test_host 
action_result.parameter.index | string |  |   main 
action_result.parameter.source | string |  |   test 
action_result.parameter.source_type | string |  |   pb 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully posted the data 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 