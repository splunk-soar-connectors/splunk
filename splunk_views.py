# File: splunk_views.py
# Copyright (c) 2014-2019 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
# --

from django.http import HttpResponse
import json


def run_query(provides, all_results, context):
    all_headers = []
    for summary, action_results in all_results:
        for result in action_results:
            parameters = result.get_param()
            # If empty display, gathers fields from each row to be used as columns
            if parameters.get('display') is None:
                headers_set = set()
                for summary, action_results in all_results:
                    for result in action_results:
                        data = result.get_data()
                        for row in data:
                            headers_set.update([key for key in row.keys() if key[0] != '_'])
                headers = sorted(headers_set)
            else:
                headers = [x.strip() for x in parameters['display'].split(',')]

            if not headers:
                all_headers.extend(["Result"])
            else:
                all_headers.extend(headers)

    context['ajax'] = True
    if 'start' not in context['QS']:
        context['headers'] = all_headers
        return '/widgets/generic_table.html'

    adjusted_names = {
        'time': '_time',
        'raw': '_raw',
    }

    start = int(context['QS']['start'][0])
    length = int(context['QS'].get('length', ['5'])[0])
    end = start + length
    cur_pos = 0
    rows = []
    total = 0
    start_col_index = 0
    end_col_index = 0
    for summary, action_results in all_results:
        for result in action_results:
            data = result.get_data()
            end_col_index = data[-1].get('end_col_index')
            total += len(data) - 1
            for item in data[:len(data) - 1]:
                cur_pos += 1
                if (cur_pos - 1) < start:
                    continue
                if (cur_pos - 1) >= end:
                    break
                row = []

                for h in all_headers[:start_col_index]:
                    row.append({ 'value': None })

                for h in all_headers[start_col_index:start_col_index + end_col_index]:
                    row.append({ 'value': item.get(adjusted_names.get(h, h)) })

                for h in all_headers[start_col_index + end_col_index:]:
                    row.append({ 'value': None })

                rows.append(row)

            start_col_index = start_col_index + end_col_index

    if len(rows) == 0:
        content = {
            "data": [[{"value": "No data found"}]],
            "recordsTotal": 1,
            "recordsFiltered": 1,
        }
    else:
        content = {
        "data": rows,
        "recordsTotal": total,
        "recordsFiltered": total,
        }
    return HttpResponse(json.dumps(content), content_type='text/javascript')
