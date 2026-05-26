# Copyright (c) 2016-2026 Splunk Inc.
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

import json

import requests
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, app

logger = getLogger()


class SplunkMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Splunk REST API endpoint to call, appended to https://<device>:<port>/. "
            "Example: 'services/search/jobs'"
        ),
        required=True,
    )
    verify_ssl: bool | None = Param(
        description="Whether to verify the SSL certificate. Defaults to the asset's 'Verify Server Certificate' setting.",
        required=False,
        default=None,
    )


class SplunkMakeRequestOutput(ActionOutput):
    status_code: int = OutputField(example_values=[200])
    response_body: str = OutputField(example_values=["{}"])

    @classmethod
    def from_response(cls, response: requests.Response) -> "SplunkMakeRequestOutput":
        return cls(status_code=response.status_code, response_body=response.text)


@app.make_request()
def http_action(
    params: SplunkMakeRequestParams, asset: Asset
) -> SplunkMakeRequestOutput:
    if params.endpoint.startswith(("http://", "https://")):
        raise ActionFailure(
            f"Invalid endpoint: {params.endpoint}. Do not include the base URL — "
            "it is derived from the asset configuration!"
        )

    base_url = f"https://{asset.device}:{asset.port}/"
    endpoint = params.endpoint.lstrip("/")
    url = f"{base_url}{endpoint}"

    auth = None
    headers: dict = {}
    if asset.api_token:
        headers["Authorization"] = f"Bearer {asset.api_token}"
    else:
        auth = (asset.username, asset.password)

    if params.headers:
        try:
            headers.update(json.loads(params.headers))
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON headers: {params.headers}") from e

    query_params = None
    if params.query_parameters:
        try:
            query_params = json.loads(params.query_parameters)
        except (json.JSONDecodeError, TypeError):
            query_string = params.query_parameters.lstrip("?")
            url = f"{url}?{query_string}" if "?" not in url else f"{url}&{query_string}"

    body = None
    if params.body:
        try:
            body = json.loads(params.body)
        except (json.JSONDecodeError, TypeError) as e:
            raise ActionFailure(f"Invalid JSON body: {params.body}") from e

    timeout = params.timeout or None
    verify = (
        params.verify_ssl if params.verify_ssl is not None else asset.verify_server_cert
    )

    try:
        response = requests.request(
            method=params.http_method,
            url=url,
            auth=auth,
            headers=headers or None,
            params=query_params,
            json=body,
            timeout=timeout,
            verify=verify,
        )
    except Exception as e:
        raise ActionFailure(f"Request failed: {e}") from e

    return SplunkMakeRequestOutput.from_response(response)
