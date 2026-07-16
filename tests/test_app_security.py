# Copyright (c) 2016-2026 Splunk Inc.

from unittest.mock import Mock

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
