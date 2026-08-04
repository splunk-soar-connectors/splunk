# Copyright (c) 2016-2026 Splunk Inc.

from io import BytesIO
from unittest.mock import Mock
from urllib.error import HTTPError as UrllibHTTPError, URLError

import pytest

from src import app as app_module
from src.app import Asset, SplunkHelper, escape_spl_string


def test_tls_verification_is_enabled_by_default():
    assert Asset.model_fields["verify_server_cert"].default is True


def test_escape_spl_string_protects_string_literal_boundaries():
    assert escape_spl_string('id" | delete \\ tail') == 'id\\" | delete \\\\ tail'


def test_xml_parser_explicitly_disables_entities(monkeypatch):
    parse = Mock(return_value={"response": {}})
    monkeypatch.setattr(app_module.xmltodict, "parse", parse)
    response = Mock(text="<response />", status_code=200)

    assert SplunkHelper._process_xml_response(response) == {"response": {}}
    parse.assert_called_once_with("<response />", disable_entities=True)


def test_non_idempotent_rest_calls_are_not_retried():
    helper = object.__new__(SplunkHelper)
    helper.asset = Mock(retry_count=3)
    helper.make_rest_call = Mock(side_effect=ConnectionError("response lost"))

    with pytest.raises(ConnectionError, match="response lost"):
        helper.make_rest_call_retry("notable_update", {"comment": "once"})

    helper.make_rest_call.assert_called_once()


def test_get_rest_calls_remain_retryable():
    helper = object.__new__(SplunkHelper)
    helper.asset = Mock(retry_count=3)
    helper.make_rest_call = Mock(
        side_effect=[ConnectionError("temporary"), {"entry": []}]
    )

    result = helper.make_rest_call_retry(
        "authentication/users", {}, method=app_module.requests.get
    )

    assert result == {"entry": []}
    assert helper.make_rest_call.call_count == 2


def test_proxy_request_returns_http_errors_to_splunk_sdk(monkeypatch):
    error = UrllibHTTPError(
        "https://splunk.example/services/search/jobs",
        401,
        "Unauthorized",
        {"Content-Type": "text/xml"},
        BytesIO(b"<response />"),
    )
    monkeypatch.setattr(app_module, "urlopen", Mock(side_effect=error))
    helper = object.__new__(SplunkHelper)
    helper.asset = Mock(verify_server_cert=True)

    response = helper._proxy_request(
        "https://splunk.example/services/search/jobs",
        {"method": "GET", "headers": []},
    )

    assert response["status"] == 401
    assert response["reason"] == "Unauthorized"
    assert response["body"].read() == b"<response />"


def test_proxy_request_returns_http_error_from_unverified_retry(monkeypatch):
    error = UrllibHTTPError(
        "https://splunk.example/services/search/jobs",
        503,
        "Unavailable",
        {"Content-Type": "text/xml"},
        BytesIO(b"<response />"),
    )
    monkeypatch.setattr(
        app_module,
        "urlopen",
        Mock(side_effect=[URLError("certificate verify failed"), error]),
    )
    helper = object.__new__(SplunkHelper)
    helper.asset = Mock(verify_server_cert=False)

    response = helper._proxy_request(
        "https://splunk.example/services/search/jobs",
        {"method": "GET", "headers": []},
    )

    assert response["status"] == 503
    assert response["reason"] == "Unavailable"


def test_proxy_request_applies_timeout_to_every_urlopen_call(monkeypatch):
    success = Mock(code=200, msg="OK", headers={"Content-Type": "text/xml"})
    success.read.return_value = b"<response />"
    open_url = Mock(side_effect=[URLError("certificate verify failed"), success])
    monkeypatch.setattr(app_module, "urlopen", open_url)
    helper = object.__new__(SplunkHelper)
    helper.asset = Mock(verify_server_cert=False)

    helper._proxy_request(
        "https://splunk.example/services/search/jobs",
        {"method": "GET", "headers": []},
    )

    assert open_url.call_args_list[0].kwargs == {
        "timeout": app_module.SPLUNK_DEFAULT_REQUEST_TIMEOUT
    }
    assert open_url.call_args_list[1].kwargs["timeout"] == (
        app_module.SPLUNK_DEFAULT_REQUEST_TIMEOUT
    )
    assert "context" in open_url.call_args_list[1].kwargs


def test_job_completion_has_a_single_total_deadline(monkeypatch):
    helper = object.__new__(SplunkHelper)
    helper.asset = Mock(splunk_job_timeout=1, retry_count=1, sleeptime_in_requests=0)
    job = Mock()
    job.is_ready.return_value = True
    job.__contains__ = Mock(side_effect=lambda key: key in {"isDone", "doneProgress"})
    job.__getitem__ = Mock(
        side_effect=lambda key: {"isDone": "0", "doneProgress": "0"}[key]
    )
    monotonic = Mock(side_effect=[10, 11])
    monkeypatch.setattr(app_module.time, "monotonic", monotonic)

    with pytest.raises(TimeoutError, match="timed out"):
        helper.wait_for_job_completion(job)
