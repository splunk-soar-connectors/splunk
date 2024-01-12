[comment]: # " File: README.md"
[comment]: # "  Copyright (c) 2016-2024 Splunk Inc."
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
(c) 2011-2024 Splunk, Inc.

## State File Permissions

Please check the permissions for the state file as mentioned below.

#### State Filepath

-   For Non-NRI Instance:
    /opt/phantom/local_data/app_states/91883aa8-9c81-470b-97a1-5d8f7995f560/{asset_id}\_state.json
-   For NRI Instance:
    /phantomcyber/local_data/app_states/91883aa8-9c81-470b-97a1-5d8f7995f560/{asset_id}\_state.json

#### State File Permissions

-   File Rights: rw-rw-r-- (664) (The splunk SOAR user should have read and write access for the state
    file)
-   File Owner: appropriate splunk SOAR user

## Required Permissions for Post Data Action
The endpoint used by the post data action is not supported on Splunk Cloud Platform. Hence, the following steps are not applicable for Splunk Cloud Platform.

For sending events to Splunk Platform, the User configured in the asset would require **edit_tcp** capability. Follow the below steps to configure

-   Login to the Splunk Platform
-   Go to **Setting > Roles**
-   Click on role of the user configured in the asset(example: user) and go to **Capabilities**
-   Search for '**edit_tcp**' in the capabilities enable it for the particular role
-   To check if the capability is given to your user, go to **Settings > Users** and in the **Edit dropdown** and select **View Capabilities**
-   Search for '**edit_tcp**' and if a tick besides it appears then the permission has been enabled for the user

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
