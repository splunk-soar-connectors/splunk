# File: splunk_views.py
#
# Copyright (c) 2014-2022 Splunk Inc.
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
def _get_ctx_result(result, provides):

    ctx_result = {}
    headers = []
    processed_data = []

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param
    ctx_result["action_name"] = provides
    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result

    if param.get("display"):
        headers = [x.strip() for x in param['display'].split(',')]
        headers = list(filter(None, headers))

    else:
        for key in data[0].keys():
            if key[0] != '_':
                headers.append(key)

    for item in data:
        header_values = dict()
        for header in headers:
            header_values[header] = item.get(header)
        processed_data.append(header_values)

    ctx_result['data'] = data
    ctx_result['processed_data'] = processed_data
    ctx_result['headers'] = headers

    return ctx_result


def display_view(provides, all_app_runs, context):

    context['results'] = results = []
    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(result, provides)
            if not ctx_result:
                continue
            results.append(ctx_result)

    return 'splunk_run_query.html'
