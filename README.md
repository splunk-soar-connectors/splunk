# Splunk

Publisher: Splunk <br>
Connector Version: 3.0.5 <br>
Product Vendor: Splunk Inc. <br>
Product Name: Splunk Enterprise <br>
Minimum Product Version: 7.0.0

This app integrates with Splunk to update data on the device, in addition to investigate and ingestion actions

### Configuration variables

This table lists the configuration variables required to operate Splunk. These variables are specified when configuring a Splunk Enterprise asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**device** | required | string | Device IP/Hostname |
**port** | optional | numeric | Port |
**username** | optional | string | Username |
**password** | optional | password | Password |
**api_token** | optional | password | API token |
**splunk_owner** | optional | string | The owner context of the namespace |
**splunk_app** | optional | string | The app context of the namespace |
**timezone** | optional | string | Splunk Server Timezone |
**verify_server_cert** | optional | boolean | Verify Server Certificate |
**on_poll_command** | optional | string | Command for query to use with On Poll |
**on_poll_query** | optional | string | Query to use with On Poll |
**on_poll_display** | optional | string | Fields to save with On Poll |
**on_poll_parse_only** | optional | boolean | Parse Only |
**max_container** | optional | numeric | Max events to ingest for Scheduled Polling (Default: 100) |
**container_update_state** | optional | numeric | Container count to update the state file |
**container_name_prefix** | optional | string | Name to give containers created via ingestion |
**container_name_values** | optional | string | Values to append to container name |
**retry_count** | optional | numeric | Number of retries |
**remove_empty_cef** | optional | boolean | Remove CEF fields having empty values from the artifact |
**sleeptime_in_requests** | optional | numeric | The time to wait for next REST call (max 120 seconds) |
**include_cim_fields** | optional | boolean | Option to keep original Splunk CIM together with SOAR CEF fields |
**splunk_job_timeout** | optional | numeric | The duration in seconds to wait before a scheduled Splunk job times out |
**use_event_id_sdi** | optional | boolean | Option to use the event_id field value as the source data identifier instead of the full event hash |

### Supported Actions

[test connectivity](#action-test-connectivity) - test connectivity <br>
[get host events](#action-get-host-events) - Get events pertaining to a host that have occurred in the last 'N' days <br>
[make request](#action-make-request) - make request <br>
[on poll](#action-on-poll) - on poll <br>
[post data](#action-post-data) - Post data to Splunk <br>
[run query](#action-run-query) - Run a search query on the Splunk device. Please escape any quotes that are part of the query string <br>
[update event](#action-update-event) - Update a notable event

## action: 'test connectivity'

test connectivity

Type: **test** <br>
Read only: **True**

Basic test for app.

#### Action Parameters

No parameters are required for this action

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'get host events'

Get events pertaining to a host that have occurred in the last 'N' days

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip_hostname** | required | Hostname/IP to search the events of | string | `ip` `host name` |
**last_n_days** | optional | Number of days ago | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.ip_hostname | string | `ip` `host name` | |
action_result.parameter.last_n_days | string | | |
action_result.data.\*.host | string | | |
action_result.data.\*.\_time | string | | |
action_result.data.\*.\_raw | string | | |
action_result.summary.sid | string | | |
action_result.summary.total_events | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'make request'

make request

Type: **generic** <br>
Read only: **False**

'make request' action for the app. Used to handle arbitrary HTTP requests with the app's asset

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**http_method** | required | The HTTP method to use for the request. | string | |
**endpoint** | required | Splunk REST API endpoint to call, appended to https://<device>:<port>/. Example: 'services/search/jobs' | string | |
**headers** | optional | The headers to send with the request (JSON object). An example is {'Content-Type': 'application/json'} | string | |
**query_parameters** | optional | Parameters to append to the URL (JSON object or query string). An example is ?key=value&key2=value2 | string | |
**body** | optional | The body to send with the request (JSON object). An example is {'key': 'value', 'key2': 'value2'} | string | |
**timeout** | optional | The timeout for the request in seconds. | numeric | |
**verify_ssl** | optional | Whether to verify the SSL certificate. Defaults to the asset's 'Verify Server Certificate' setting. | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.http_method | string | | |
action_result.parameter.endpoint | string | | |
action_result.parameter.headers | string | | |
action_result.parameter.query_parameters | string | | |
action_result.parameter.body | string | | |
action_result.parameter.timeout | numeric | | |
action_result.parameter.verify_ssl | boolean | | |
action_result.data.\*.status_code | numeric | | 200 |
action_result.data.\*.response_body | string | | {} |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'on poll'

on poll

Type: **ingest** <br>
Read only: **True**

Callback action for the on_poll ingest functionality

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**start_time** | optional | Start of time range, in epoch time (milliseconds). | numeric | |
**end_time** | optional | End of time range, in epoch time (milliseconds). | numeric | |
**container_count** | optional | Maximum number of container records to query for. | numeric | |
**artifact_count** | optional | Maximum number of artifact records to query for. | numeric | |
**container_id** | optional | Comma-separated list of container IDs to limit the ingestion to. | string | |

#### Action Output

No Output

## action: 'post data'

Post data to Splunk

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**data** | required | Data to post | string | |
**host** | optional | Host for event | string | `ip` `host name` |
**index** | optional | Index to send event to | string | |
**source** | optional | Source for event | string | |
**source_type** | optional | Type of source for event | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.data | string | | |
action_result.parameter.host | string | `ip` `host name` | |
action_result.parameter.index | string | | |
action_result.parameter.source | string | | |
action_result.parameter.source_type | string | | |
action_result.data.\*.status | string | | |
action_result.data.\*.message | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'run query'

Run a search query on the Splunk device. Please escape any quotes that are part of the query string

Type: **investigate** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**command** | optional | Beginning command (in Splunk Processing Language) | string | |
**query** | required | Query to run (in Splunk Processing Language) | string | `splunk query` |
**display** | optional | Display fields (comma-separated) | string | |
**parse_only** | optional | Parse only | boolean | |
**add_raw_field** | optional | Ingest \_raw field data | boolean | |
**attach_result** | optional | Attach result to the vault | boolean | |
**start_time** | optional | Earliest time modifier | string | |
**end_time** | optional | Latest time modifier | string | |
**search_mode** | optional | Search mode | string | |
**time_format** | optional | Custom timestamp format | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.command | string | | |
action_result.parameter.query | string | `splunk query` | |
action_result.parameter.display | string | | |
action_result.parameter.parse_only | boolean | | |
action_result.parameter.add_raw_field | boolean | | |
action_result.parameter.attach_result | boolean | | |
action_result.parameter.start_time | string | | |
action_result.parameter.end_time | string | | |
action_result.parameter.search_mode | string | | |
action_result.parameter.time_format | string | | |
action_result.summary.sid | string | | |
action_result.summary.total_events | numeric | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

## action: 'update event'

Update a notable event

Type: **generic** <br>
Read only: **False**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**event_ids** | required | Event ID to update | string | `splunk notable event id` |
**owner** | optional | New owner for the event | string | |
**status** | optional | New status for the event | string | |
**integer_status** | optional | Integer representing custom status value | string | |
**urgency** | optional | New urgency for the event | string | |
**comment** | optional | New comment for the event | string | |
**disposition** | optional | New disposition field | string | |
**integer_disposition** | optional | Integer representing custom disposition value | string | |
**wait_for_confirmation** | optional | Validate event_ids | boolean | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failure |
action_result.message | string | | |
action_result.parameter.event_ids | string | `splunk notable event id` | |
action_result.parameter.owner | string | | |
action_result.parameter.status | string | | |
action_result.parameter.integer_status | string | | |
action_result.parameter.urgency | string | | |
action_result.parameter.comment | string | | |
action_result.parameter.disposition | string | | |
action_result.parameter.integer_disposition | string | | |
action_result.parameter.wait_for_confirmation | boolean | | |
action_result.data.\*.status | string | | |
action_result.data.\*.failure_count | numeric | | |
action_result.data.\*.message | string | | |
action_result.data.\*.success | boolean | | True False |
action_result.data.\*.success_count | numeric | | |
action_result.summary.sid | string | | |
action_result.summary.updated_event_id | string | | |
summary.total_objects | numeric | | 1 |
summary.total_objects_successful | numeric | | 1 |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2026 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
