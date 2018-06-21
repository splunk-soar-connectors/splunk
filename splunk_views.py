# --
# File: ./splunk/splunk_views.py
#
# Copyright (c) Phantom Cyber Corporation, 2014-2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber.
#
# --

from django.http import HttpResponse
import json


def run_query(provides, all_results, context):
    # Assumes valid all_results
    result = all_results[0][1][0]
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
