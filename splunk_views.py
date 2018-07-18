# --
# File: ./splunk/splunk_views.py
#
# Copyright (c) 2014-2018 Splunk Inc.
#
# SPLUNK CONFIDENTIAL – Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.
#
#
# --

from django.http import HttpResponse
import json


def run_query(provides, all_results, context):
    try:
        result = all_results[0][1][0]
    except IndexError:
        content = {
          "data": [],
          "recordsTotal": 0,
          "recordsFiltered": 0,
        }
        return HttpResponse(json.dumps(content), content_type='text/javascript')

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

    context['ajax'] = True
    if 'start' not in context['QS']:
        context['headers'] = headers
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
    for summary, action_results in all_results:
        for result in action_results:
            data = result.get_data()
            total += len(data)
            for item in data:
                cur_pos += 1
                if (cur_pos - 1) < start:
                    continue
                if (cur_pos - 1) >= end:
                    break
                row = []

                for h in headers:
                    row.append({ 'value': item.get(adjusted_names.get(h, h)) })
                rows.append(row)

    content = {
      "data": rows,
      "recordsTotal": total,
      "recordsFiltered": total,
    }
    return HttpResponse(json.dumps(content), content_type='text/javascript')
